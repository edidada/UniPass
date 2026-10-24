package com.unipass.server;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuditArchiveIT {
    private static final UUID OPERATOR = new UUID(0, 1);
    private static final UUID AUDITOR = new UUID(0, 2);
    private static final UUID NON_ADMIN = new UUID(0, 3);
    private static final Instant NOW = Instant.parse("2026-10-24T00:00:00Z");
    private EmbeddedPostgres pg;
    private JdbcTemplate jdbc;
    private TransactionTemplate tx;
    private AuditArchiveService archives;
    private AuditMaintenanceService maintenance;
    private AccountState accounts;
    private MfaService mfa;

    @BeforeAll void start() throws Exception {
        System.setProperty("ot.epg.working-dir",
                Files.createDirectories(Path.of("target", "audit-archive", "postgres")).toAbsolutePath().toString());
        pg = EmbeddedPostgres.builder().setPort(0).setServerConfig("listen_addresses", "127.0.0.1").start();
        jdbc = new JdbcTemplate(pg.getPostgresDatabase());
        tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
        tx.setTimeout(10);
        Clock clock = Clock.fixed(NOW, ZoneId.of("UTC"));
        archives = new AuditArchiveService(jdbc, tx, clock);
        accounts = Mockito.mock(AccountState.class);
        mfa = Mockito.mock(MfaService.class);
        Mockito.when(mfa.recent(Mockito.any())).thenReturn(true);
        Mockito.when(accounts.roles(OPERATOR)).thenReturn(List.of("ROLE_SYSTEM_ADMIN"));
        Mockito.when(accounts.roles(AUDITOR)).thenReturn(List.of("ROLE_ADMIN_AUDIT"));
        Mockito.when(accounts.roles(NON_ADMIN)).thenReturn(List.of("ROLE_USER"));
        maintenance = new AuditMaintenanceService(archives, tx, accounts, mfa, new AdminAuditService(jdbc, clock), clock);
    }
    @BeforeEach void seed() {
        Flyway.configure().dataSource(jdbc.getDataSource()).cleanDisabled(false).load().clean();
        Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
        jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('archive-test','1')");
        for (UUID id : List.of(OPERATOR, AUDITOR, NON_ADMIN))
            jdbc.update("""
                    INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch)
                    VALUES (?,?,?,'OPENLDAP','uid=x','Test','ACTIVE','archive-test',1,5)
                    """, id, "archive-" + id.toString().substring(24), UUID.randomUUID());
    }
    private IdentityPrincipal principal(UUID user, List<String> roles) {
        return new IdentityPrincipal(user, 5, NOW, roles, NOW, IdentityPrincipal.Method.PASSWORD, NOW, UUID.randomUUID());
    }
    private IdentityPrincipal operator() { return principal(OPERATOR, List.of("ROLE_SYSTEM_ADMIN")); }
    private UUID audit(String action, Instant at) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO auth_audit(id,action,trace_id,detail,created_at) VALUES (?,?,?,'{}'::jsonb,?)",
                id, action, UUID.randomUUID(), Timestamp.from(at));
        return id;
    }
    private int live() { return jdbc.queryForObject("SELECT count(*) FROM auth_audit", Integer.class); }
    private int archived() { return jdbc.queryForObject("SELECT count(*) FROM audit_archive", Integer.class); }
    private ResponseStatusException rejected(Runnable call) {
        try { call.run(); throw new AssertionError("Expected rejection"); }
        catch (ResponseStatusException e) { return e; }
    }

    @Test void archiveMovesOnlyRowsOlderThanTheCutoffAndVerifies() {
        UUID old = audit("ROLE_GRANTED", NOW.minus(Duration.ofDays(200)));
        UUID old2 = audit("ROLE_REVOKED", NOW.minus(Duration.ofDays(190)));
        UUID recent = audit("ROLE_GRANTED", NOW.minus(Duration.ofDays(10)));
        var batch = maintenance.archive(operator(), NOW.minus(Duration.ofDays(180)), 100, "203.0.113.9");
        assertNotNull(batch);
        assertEquals(2, batch.rows());
        assertEquals(64, batch.digest().length());
        assertEquals(2, archived());
        // Live table keeps the recent row plus the AUDIT_ARCHIVED entry written by this operation.
        assertEquals(2, live());
        assertNotNull(jdbc.queryForObject("SELECT id FROM auth_audit WHERE id=?", UUID.class, recent));
        assertTrue(archives.verify(batch.id()).intact());
        assertEquals(1, archives.batches(10).size());
        Map<String, Object> entry = jdbc.queryForMap("SELECT detail->>'batch_id' AS batch_id, detail->>'rows' AS rows, source_ip FROM auth_audit WHERE action='AUDIT_ARCHIVED'");
        assertEquals(batch.id().toString(), entry.get("batch_id"));
        assertEquals("2", entry.get("rows"));
        assertEquals("203.0.113.9", entry.get("source_ip"));
    }

    @Test void restoreFirstChecksIntegrityAndIsIdempotent() {
        audit("ROLE_GRANTED", NOW.minus(Duration.ofDays(200)));
        audit("ROLE_REVOKED", NOW.minus(Duration.ofDays(190)));
        var batch = maintenance.archive(operator(), NOW.minus(Duration.ofDays(180)), 100, null);
        assertNotNull(batch);
        assertEquals(2, maintenance.restore(operator(), batch.id(), "198.51.100.7"));
        // Two restored rows plus the archival and restore audit entries.
        assertEquals(4, live());
        assertEquals(0, maintenance.restore(operator(), batch.id(), null), "a repeated restore inserts nothing");
        // Both attempts stay traceable even when the second restored no rows.
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action='AUDIT_RESTORED'", Integer.class));
        // Tampering with an archived row is detected and blocks the restore.
        jdbc.update("UPDATE audit_archive SET detail='{\"role\":\"TAMPERED\"}'::jsonb WHERE id=(SELECT id FROM audit_archive WHERE batch_id=? ORDER BY id LIMIT 1)", batch.id());
        assertFalse(archives.verify(batch.id()).intact());
        assertEquals(409, rejected(() -> maintenance.restore(operator(), batch.id(), null)).getStatusCode().value());
    }

    @Test void emptyArchiveCreatesNoBatchAndBatchSizeIsBounded() {
        audit("ROLE_GRANTED", NOW.minus(Duration.ofDays(10)));
        assertNull(maintenance.archive(operator(), NOW.minus(Duration.ofDays(180)), 100, null));
        assertTrue(archives.batches(10).isEmpty());
        for (int i = 0; i < 5; i++) audit("ROLE_GRANTED", NOW.minus(Duration.ofDays(200 + i)));
        var limited = maintenance.archive(operator(), NOW.minus(Duration.ofDays(180)), 2, null);
        assertNotNull(limited);
        assertEquals(2, limited.rows());
        assertEquals(2, archived());
        assertEquals(3, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE created_at < ?", Integer.class,
                Timestamp.from(NOW.minus(Duration.ofDays(180)))));
    }

    @Test void retentionOperationsEnforceStrongAuthorityAndAuditorsStayReadOnly() {
        IdentityPrincipal auditor = principal(AUDITOR, List.of("ROLE_ADMIN_AUDIT"));
        IdentityPrincipal plain = principal(NON_ADMIN, List.of("ROLE_USER"));
        audit("ROLE_GRANTED", NOW.minus(Duration.ofDays(200)));
        assertEquals(403, rejected(() -> maintenance.archive(plain, NOW.minus(Duration.ofDays(180)), 10, null)).getStatusCode().value());
        assertEquals(403, rejected(() -> maintenance.archive(auditor, NOW.minus(Duration.ofDays(180)), 10, null)).getStatusCode().value());
        var batch = maintenance.archive(operator(), NOW.minus(Duration.ofDays(180)), 10, null);
        assertNotNull(batch);
        assertEquals(1, maintenance.batches(auditor, 10).size());
        assertTrue(maintenance.verify(auditor, batch.id()).intact());
        assertEquals(403, rejected(() -> maintenance.restore(auditor, batch.id(), null)).getStatusCode().value());
        assertEquals(404, rejected(() -> archives.verify(new UUID(9, 9))).getStatusCode().value());
        assertThrows(ResponseStatusException.class, () -> maintenance.archive(operator(), NOW.minus(Duration.ofDays(180)), 0, null));
        assertThrows(ResponseStatusException.class, () -> maintenance.archive(operator(), NOW.minus(Duration.ofDays(180)), 10_001, null));
        assertThrows(ResponseStatusException.class, () -> maintenance.archive(operator(), null, 10, null));
        // A system-triggered archive is still attributable in the audit trail.
        jdbc.update("UPDATE auth_audit SET created_at=now()-interval '400 days' WHERE action='AUDIT_ARCHIVED'");
        audit("ROLE_GRANTED", NOW.minus(Duration.ofDays(400)));
        var system = maintenance.archiveDue(NOW.minus(Duration.ofDays(180)), 10);
        assertNotNull(system);
        assertEquals("system", jdbc.queryForObject("SELECT detail->>'operator' FROM auth_audit WHERE action='AUDIT_ARCHIVED' AND detail->>'batch_id'=?", String.class, system.id().toString()));
        // The scheduled worker is disabled unless the property is set; the service itself is covered above.
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM audit_archive_batch WHERE id=?", Integer.class, system.id()));
    }

    @AfterAll void stop() throws Exception { if (pg != null) pg.close(); }
}
