package com.unipass.server;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Service-level T8 verification on real Postgres: the authority matrix,
 * transaction-internal role recheck, one-time secrets, bounded rotation
 * overlap, disable-wins fencing and audit atomicity. HTTP and framework-level
 * behavior (authorization/token endpoints, dual verifier) is covered by
 * ClientManagementHttpIT.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClientApplicationIT {
    private static final UUID APP_ADMIN = new UUID(0, 1);
    private static final UUID AUDITOR = new UUID(0, 5);
    private static final UUID USER_OPERATOR = new UUID(0, 6);
    private static final List<String> APP = List.of(AdminAuthorities.APP_ADMIN);
    private EmbeddedPostgres pg;
    private JdbcTemplate jdbc;
    private TransactionTemplate tx;
    private AdminAuditService audit;
    private ClientManagementService clients;
    private AccountState accounts;
    private MfaService mfa;
    private RegisteredClientRepository repository;
    private ClientRegistrationService registrations;
    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-23T00:00:00Z"));

    @BeforeAll void start() throws Exception {
        System.setProperty("ot.epg.working-dir",
                Files.createDirectories(Path.of("target", "client-application", "postgres")).toAbsolutePath().toString());
        pg = EmbeddedPostgres.builder().setPort(0).setServerConfig("listen_addresses", "127.0.0.1").start();
        jdbc = new JdbcTemplate(pg.getPostgresDatabase());
        tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
        tx.setTimeout(10);
        Clock clock = new Clock() {
            @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return now.get(); }
        };
        audit = new AdminAuditService(jdbc, clock);
        accounts = Mockito.mock(AccountState.class);
        Mockito.when(accounts.roles(APP_ADMIN)).thenReturn(APP);
        Mockito.when(accounts.roles(AUDITOR)).thenReturn(List.of(AdminAuthorities.AUDITOR));
        Mockito.when(accounts.roles(USER_OPERATOR)).thenReturn(List.of(AdminAuthorities.USER_OPERATOR));
        mfa = Mockito.mock(MfaService.class);
        Mockito.when(mfa.recent(Mockito.any())).thenReturn(true);
        repository = new JdbcRegisteredClientRepository(jdbc);
        registrations = new ClientRegistrationService(repository, false);
        clients = new ClientManagementService(jdbc, tx, accounts, audit, mfa, clock, registrations, repository);
    }

    @BeforeEach void seed() {
        Flyway.configure().dataSource(jdbc.getDataSource()).cleanDisabled(false).load().clean();
        Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
        jdbc.update("""
                INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch)
                VALUES (?,'app-admin',?,'OPENLDAP','uid=admin','Admin','ACTIVE','client-test',1,5)
                """, APP_ADMIN, UUID.randomUUID());
        jdbc.update("INSERT INTO iam_user_role(user_id,role) VALUES (?,'ROLE_APP_ADMIN') ON CONFLICT DO NOTHING", APP_ADMIN);
        for (UUID other : new UUID[] { AUDITOR, USER_OPERATOR })
            jdbc.update("""
                    INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch)
                    VALUES (?,'viewer',?,'OPENLDAP','uid=viewer','Viewer','ACTIVE','client-test',1,5)
                    """, other, UUID.randomUUID());
    }

    private IdentityPrincipal principal(UUID id, List<String> roles) {
        // Password proof is anchored to the injected clock so the recent window holds.
        return new IdentityPrincipal(id, 5, now.get(), roles, now.get(), IdentityPrincipal.Method.PASSWORD, now.get(), UUID.randomUUID());
    }

    private IdentityPrincipal appAdmin() { return principal(APP_ADMIN, APP); }

    private ClientRegistrationService.Spec spec(String clientId, ClientRegistrationService.Kind kind) {
        return new ClientRegistrationService.Spec(clientId, "合同系统", kind,
                List.of("https://app.example.com/callback"), List.of("https://app.example.com/bye"),
                Set.of("openid", "profile"), null, "采购部-张三");
    }

    private ResponseStatusException rejected(Runnable call) {
        try { call.run(); throw new AssertionError("Expected rejection"); }
        catch (ResponseStatusException e) { return e; }
    }

    private ClientManagementService.IssuedSecret registerConfidential(String clientId) {
        return clients.register(appAdmin(), spec(clientId, ClientRegistrationService.Kind.CONFIDENTIAL),
                "register-key-" + clientId, "新应用接入");
    }

    private int auditCount(String action) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action=?", Integer.class, action);
    }

    private boolean actionRow(String clientId, String verb) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM iam_client_action WHERE registered_client_id=? AND action=?)", Boolean.class, clientId, verb));
    }

    @Test void appAdminMutatesButAuditorAndUserOperatorArePowerless() {
        registerConfidential("conf-app");
        // APP_ADMIN holds the lifecycle; AUDITOR and USER_OPERATOR hold no
        // mutation authority in this increment (least privilege, no inference).
        IdentityPrincipal auditor = principal(AUDITOR, List.of(AdminAuthorities.AUDITOR));
        IdentityPrincipal operator = principal(USER_OPERATOR, List.of(AdminAuthorities.USER_OPERATOR));
        assertEquals(403, rejected(() -> clients.register(auditor, spec("aud-neg", ClientRegistrationService.Kind.CONFIDENTIAL), "negative-key-audit1", "越界尝试")).getStatusCode().value());
        assertEquals(403, rejected(() -> clients.setState(auditor, "conf-app", false, "negative-key-audit2", "越界尝试")).getStatusCode().value());
        assertEquals(403, rejected(() -> clients.rotate(auditor, "conf-app", new ClientManagementService.RotationRequest(60), "negative-key-audit3", "越界尝试")).getStatusCode().value());
        assertEquals(403, rejected(() -> clients.register(operator, spec("spa-neg", ClientRegistrationService.Kind.SPA), "negative-key-oper01", "越界尝试")).getStatusCode().value());
        assertEquals(403, rejected(() -> clients.update(operator, "conf-app", new ClientManagementService.UpdateRequest(
                "改名", "采购部-张三", List.of("https://app.example.com/callback"), List.of(), Set.of("openid", "profile"), null),
                "negative-key-oper02", "越界尝试")).getStatusCode().value());
        assertEquals(403, rejected(() -> clients.setState(operator, "conf-app", false, "negative-key-oper03", "越界尝试")).getStatusCode().value());
        assertEquals(403, rejected(() -> clients.rotate(operator, "conf-app", new ClientManagementService.RotationRequest(60), "negative-key-oper04", "越界尝试")).getStatusCode().value());
        // Nothing was created or mutated by the excluded roles.
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM oauth2_registered_client WHERE client_id IN ('aud-neg','spa-neg')", Integer.class));
        assertEquals(Boolean.TRUE, jdbc.queryForObject("SELECT enabled FROM oauth2_registered_client WHERE client_id='conf-app'", Boolean.class));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM iam_client_action WHERE actor_id<>?", Integer.class, APP_ADMIN));
        assertEquals(1, auditCount("CLIENT_REGISTERED"));
    }

    @Test void inTransactionRoleRevocationAbortsTheClientWrite() {
        // The pre-transaction guard still sees the operator, but the in-transaction
        // recheck under the actor row lock observes a concurrent revocation: the
        // registration and its action row roll back together.
        Mockito.when(accounts.roles(APP_ADMIN)).thenReturn(APP, List.of("ROLE_USER"));
        assertEquals(403, rejected(() -> clients.register(appAdmin(), spec("revoked-race", ClientRegistrationService.Kind.CONFIDENTIAL),
                "toctou-key-register01", "撤销竞态")).getStatusCode().value());
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM oauth2_registered_client WHERE client_id='revoked-race'", Integer.class));
        assertTrue(jdbc.queryForList("SELECT action FROM iam_client_action WHERE registered_client_id='revoked-race'", String.class).isEmpty());
        assertEquals(0, auditCount("CLIENT_REGISTERED"));
        Mockito.when(accounts.roles(APP_ADMIN)).thenReturn(APP);
    }

    @Test void registerReplayNeverReExposesTheOneTimeSecret() {
        String key = "idempotent-key-00000001";
        ClientRegistrationService.Spec request = spec("replay-app", ClientRegistrationService.Kind.CONFIDENTIAL);
        ClientManagementService.IssuedSecret first = clients.register(appAdmin(), request, key, "首次登记");
        assertNotNull(first.secret());
        assertTrue(first.secretKeyId().startsWith("sk-"));
        assertFalse(first.replay());
        // Lost-response replay: read-only confirmation, identical key id, no secret.
        ClientManagementService.IssuedSecret replay = clients.register(appAdmin(), request, key, "首次登记");
        assertTrue(replay.replay());
        assertNull(replay.secret());
        assertEquals(first.secretKeyId(), replay.secretKeyId());
        assertEquals(1, auditCount("CLIENT_REGISTERED"));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM iam_client_action WHERE registered_client_id='replay-app'", Integer.class));
    }

    @Test void duplicateRegisterIsRefusedWithNoActionRow() {
        registerConfidential("dup-app");
        // A second registration for an existing client fails inside the
        // transaction after the action insert: the whole write rolls back.
        assertEquals(409, rejected(() -> clients.register(appAdmin(), spec("dup-app", ClientRegistrationService.Kind.CONFIDENTIAL),
                "duplicate-key-0000001", "重复登记")).getStatusCode().value());
        assertEquals(0, jdbc.queryForObject(
                "SELECT count(*) FROM iam_client_action WHERE registered_client_id='dup-app' AND idempotency_key='duplicate-key-0000001'", Integer.class));
        assertFalse(actionRow("dup-app", "UPDATE"));
        assertEquals(1, auditCount("CLIENT_REGISTERED"));
    }

    @Test void updateEnforcesTheStrictPolicyAndKeepsTheFixedType() {
        ClientManagementService.IssuedSecret issued = registerConfidential("update-app");
        String clientId = issued.clientId();
        // Duplicated redirect URIs and a missing owner are refused before any write.
        assertEquals(400, rejected(() -> clients.update(appAdmin(), clientId, new ClientManagementService.UpdateRequest(
                "合同系统", "采购部-张三", List.of("https://app.example.com/callback", "https://app.example.com/callback"),
                List.of(), Set.of("openid", "profile"), null), "update-key-invalid01", "改地址")).getStatusCode().value());
        assertEquals(400, rejected(() -> clients.update(appAdmin(), clientId, new ClientManagementService.UpdateRequest(
                "合同系统", null, List.of("https://app.example.com/callback"), List.of(), Set.of("openid", "profile"), null),
                "update-key-invalid02", "改地址")).getStatusCode().value());
        // A public (NATIVE) client can never be turned into a confidential one by an update.
        clients.register(appAdmin(), spec("native-update", ClientRegistrationService.Kind.NATIVE), "update-key-native01", "本机应用");
        ClientManagementService.ClientDetail publicDetail = clients.update(appAdmin(), "native-update", new ClientManagementService.UpdateRequest(
                "合同系统", "采购部-张三", List.of("https://app.example.com/callback"), List.of("https://app.example.com/bye"),
                Set.of("openid", "email"), null), "update-key-native02", "改地址");
        assertEquals(ClientManagementService.KIND_NATIVE, publicDetail.kind());
        assertFalse(publicDetail.confidential());
        // The confidential client keeps its basic authentication after updates.
        ClientManagementService.ClientDetail detail = clients.update(appAdmin(), clientId, new ClientManagementService.UpdateRequest(
                "合同系统-二", "采购部-张三", List.of("https://app.example.com/callback2"), List.of(),
                Set.of("openid", "profile", "api.read"), "https://app.example.com/logout/backchannel"),
                "update-key-valid001", "改地址与负责人");
        assertEquals("合同系统-二", detail.name());
        assertEquals("采购部-张三", detail.owner());
        assertEquals(List.of("https://app.example.com/callback2"), detail.redirectUris());
        assertEquals("https://app.example.com/logout/backchannel", detail.backchannelUri());
        assertEquals(ClientManagementService.KIND_CONFIDENTIAL, detail.kind());
        assertTrue(detail.confidential());
        assertEquals("client_secret_basic", jdbc.queryForObject(
                "SELECT client_authentication_methods FROM oauth2_registered_client WHERE client_id=?", String.class, clientId));
        assertEquals(1, jdbc.queryForObject(
                "SELECT count(*) FROM iam_client_action WHERE registered_client_id='native-update' AND action='UPDATE'", Integer.class));
        assertEquals(1, jdbc.queryForObject(
                "SELECT count(*) FROM iam_client_action WHERE registered_client_id=? AND action='UPDATE'", Integer.class, clientId));
    }

    @Test void rotationOverlapIsBoundedByTheClockAndOlderMaterialIsNeverRestored() {
        ClientManagementService.IssuedSecret registered = registerConfidential("rotate-app");
        String clientId = registered.clientId();
        String originalKey = jdbc.queryForObject("SELECT secret_key_id FROM oauth2_registered_client WHERE client_id=?", String.class, clientId);
        // Out-of-range overlaps are refused before any state change.
        assertEquals(400, rejected(() -> clients.rotate(appAdmin(), clientId, new ClientManagementService.RotationRequest(-1),
                "rotate-key-bad-001", "轮换")).getStatusCode().value());
        assertEquals(400, rejected(() -> clients.rotate(appAdmin(), clientId, new ClientManagementService.RotationRequest(3601),
                "rotate-key-bad-002", "轮换")).getStatusCode().value());
        ClientManagementService.IssuedSecret first = clients.rotate(appAdmin(), clientId, new ClientManagementService.RotationRequest(300), "rotate-key-first01", "按周期轮换");
        assertNotNull(first.secret());
        assertEquals(now.get().plusSeconds(300), first.overlapUntil());
        // The retired verifier stays valid strictly before the overlap deadline.
        Timestamp until = jdbc.queryForObject("SELECT secret_previous_until FROM oauth2_registered_client WHERE client_id=?", Timestamp.class, clientId);
        assertEquals(now.get().plusSeconds(300), until.toInstant());
        now.set(now.get().plusSeconds(299));
        assertTrue(jdbc.queryForObject("SELECT secret_previous_key_id FROM oauth2_registered_client WHERE client_id=?", String.class, clientId) != null);
        now.set(now.get().plusSeconds(1)); // exactly at the deadline: the old verifier is expired (isBefore is strict)
        ClientManagementService.IssuedSecret second = clients.rotate(appAdmin(), clientId, new ClientManagementService.RotationRequest(120), "rotate-key-second1", "再次轮换");
        assertNotNull(second.secret());
        assertNotEquals(first.secretKeyId(), second.secretKeyId());
        // The second rotation retires the directly previous verifier only: the older
        // material was replaced and can neither be restored nor extended.
        assertEquals(first.secretKeyId(),
                jdbc.queryForObject("SELECT secret_previous_key_id FROM oauth2_registered_client WHERE client_id=?", String.class, clientId));
        assertNotEquals(originalKey, jdbc.queryForObject(
                "SELECT secret_previous_key_id FROM oauth2_registered_client WHERE client_id=?", String.class, clientId));
        // Zero overlap means the old verifier is Dead immediately (strict isBefore).
        ClientManagementService.IssuedSecret third = clients.rotate(appAdmin(), clientId, new ClientManagementService.RotationRequest(0), "rotate-key-third01", "零重叠");
        assertNull(third.overlapUntil());
        // Replay of the same rotation key confirms without re-exposing the secret.
        ClientManagementService.IssuedSecret replay = clients.rotate(appAdmin(), clientId, new ClientManagementService.RotationRequest(0), "rotate-key-third01", "零重叠");
        assertTrue(replay.replay());
        assertNull(replay.secret());
        assertEquals(third.secretKeyId(), replay.secretKeyId());
    }

    @Test void publicClientsCanNeverGainSecretsThroughRotation() {
        clients.register(appAdmin(), spec("public-spa", ClientRegistrationService.Kind.SPA), "register-key-public01", "单页应用");
        ResponseStatusException failure = rejected(() -> clients.rotate(appAdmin(), "public-spa",
                new ClientManagementService.RotationRequest(60), "rotate-key-public1", "越权轮换"));
        assertEquals(400, failure.getStatusCode().value());
        assertEquals("Client is not confidential", failure.getReason());
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM iam_client_action WHERE registered_client_id='public-spa'", Integer.class));
        assertEquals(0, auditCount("CLIENT_SECRET_ROTATED"));
    }

    @Test void disableWinsRevokeFenceAndRollbackStayAtomic() {
        ClientManagementService.IssuedSecret registered = registerConfidential("fence-app");
        String registeredId = registered.registeredId();
        // One active authorization plus its RP session: disabling fires the
        // framework logout trigger and must fence unfinished delivery tasks.
        jdbc.update("INSERT INTO oauth2_authorization(id,registered_client_id,principal_name,authorization_grant_type) VALUES (?,?,?,'authorization_code')",
                "auth-1", registeredId, APP_ADMIN.toString());
        jdbc.update("INSERT INTO oidc_rp_session(authorization_id,user_id,client_id,target_uri,sid,login_authenticated_at) VALUES ('auth-1',?,?,'https://app.example.com/','sid-1',now())",
                APP_ADMIN, registered.clientId());
        jdbc.update("INSERT INTO oidc_logout_task(id,authorization_id,user_id,client_id,target_uri,sid,login_authenticated_at) VALUES (?,?,?,?,?,?,now())",
                UUID.randomUUID(), "auth-2", APP_ADMIN, registered.clientId(), "https://app.example.com/", "sid-2");
        jdbc.update("INSERT INTO oauth2_authorization(id,registered_client_id,principal_name,authorization_grant_type) VALUES ('auth-2',?,?, 'authorization_code')",
                registeredId, APP_ADMIN.toString());
        ClientManagementService.ClientReview disable = clients.setState(appAdmin(), registered.clientId(), false, "disable-key-00000001", "合同到期下线");
        assertFalse(disable.enabled());
        assertFalse(disable.replay());
        assertEquals(Boolean.FALSE, jdbc.queryForObject("SELECT enabled FROM oauth2_registered_client WHERE client_id=?", Boolean.class, registered.clientId()));
        // Every authorization is revoked in the same transaction.
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM oauth2_authorization WHERE registered_client_id=? AND revoked", Integer.class, registeredId));
        // The trigger-enqueued task and the pre-existing PENDING task are both fenced DEAD.
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM oidc_logout_task WHERE client_id=? AND state='DEAD'", Integer.class, registered.clientId()));
        assertEquals(1, auditCount("CLIENT_DISABLED"));
        // Audit detail never carries secret material.
        String detailBlob = jdbc.queryForObject("SELECT string_agg(detail::text, ' ') FROM auth_audit", String.class);
        assertNotNull(detailBlob);
        assertFalse(detailBlob.contains(registered.secret()));
        assertFalse(detailBlob.toLowerCase().contains("secret"));
        // Enabling the client again does not resurrect revoked authorizations.
        ClientManagementService.ClientReview enable = clients.setState(appAdmin(), registered.clientId(), true, "enable-key-000000001", "合同重新上线");
        assertTrue(enable.enabled());
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM oauth2_authorization WHERE registered_client_id=? AND revoked", Integer.class, registeredId));
        // Replay of the disable stays idempotent and changes nothing more.
        ClientManagementService.ClientReview replay = clients.setState(appAdmin(), registered.clientId(), false, "disable-key-00000001", "合同到期下线");
        assertTrue(replay.replay());
        assertEquals(Boolean.FALSE, jdbc.queryForObject("SELECT enabled FROM oauth2_registered_client WHERE client_id=?", Boolean.class, registered.clientId()));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM iam_client_action WHERE registered_client_id=? AND action='DISABLE'", Integer.class, registered.clientId()));
    }

    @Test void auditFailureRollsBackTheClientMutationTogether() {
        ClientManagementService.IssuedSecret registered = registerConfidential("atomic-app");
        jdbc.execute("CREATE FUNCTION audit_barrier() RETURNS trigger AS $b$ BEGIN RAISE EXCEPTION 'audit blocked'; END $b$ LANGUAGE plpgsql");
        jdbc.execute("CREATE TRIGGER audit_barrier BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION audit_barrier()");
        assertThrows(org.springframework.dao.DataAccessException.class, () ->
                clients.setState(appAdmin(), registered.clientId(), false, "atomic-key-00000001", "审计失败回滚"));
        jdbc.execute("DROP TRIGGER audit_barrier ON auth_audit");
        jdbc.execute("DROP FUNCTION audit_barrier()");
        // Nothing moved: the client stays enabled, no action, no audit.
        assertEquals(Boolean.TRUE, jdbc.queryForObject("SELECT enabled FROM oauth2_registered_client WHERE client_id=?", Boolean.class, registered.clientId()));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM oauth2_authorization WHERE registered_client_id=? AND revoked", Integer.class, registered.registeredId()));
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM iam_client_action WHERE registered_client_id=? AND action='DISABLE'", Integer.class, registered.clientId()));
        assertEquals(0, auditCount("CLIENT_DISABLED"));
        // Retried after the barrier is removed, the same key succeeds cleanly.
        ClientManagementService.ClientReview disable = clients.setState(appAdmin(), registered.clientId(), false, "atomic-key-00000001", "审计失败回滚");
        assertFalse(disable.enabled());
        assertEquals(1, auditCount("CLIENT_DISABLED"));
    }

    @AfterAll void stop() throws Exception { if (pg != null) pg.close(); }
}
