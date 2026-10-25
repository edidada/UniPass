package com.unipass.server;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClientAdminIT {
    private static final UUID OPERATOR = new UUID(0, 1);
    private static final UUID APP_ADMIN = new UUID(0, 2);
    private static final UUID NON_ADMIN = new UUID(0, 3);
    private static final UUID AUDITOR = new UUID(0, 5);
    private EmbeddedPostgres pg;
    private JdbcTemplate jdbc;
    private TransactionTemplate tx;
    private RegisteredClientRepository clients;
    private ClientAdminService service;
    private PreviousClientSecretAuthenticationProvider previous;
    private AccountState accounts;
    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-24T00:00:00Z"));
    private final Duration overlap = Duration.ofHours(1);

    @BeforeAll void start() throws Exception {
        System.setProperty("ot.epg.working-dir",
                Files.createDirectories(Path.of("target", "client-admin", "postgres")).toAbsolutePath().toString());
        pg = EmbeddedPostgres.builder().setPort(0).setServerConfig("listen_addresses", "127.0.0.1").start();
        jdbc = new JdbcTemplate(pg.getPostgresDatabase());
        tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
        tx.setTimeout(10);
        Clock clock = new Clock() {
            @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return now.get(); }
        };
        clients = new JdbcRegisteredClientRepository(jdbc);
        Environment env = Mockito.mock(Environment.class);
        Mockito.when(env.getProperty("unipass.clients.secret-rotation-window", Duration.class, ClientAdminService.DEFAULT_OVERLAP))
                .thenReturn(overlap);
        accounts = Mockito.mock(AccountState.class);
        Mockito.when(accounts.roles(OPERATOR)).thenReturn(List.of("ROLE_SYSTEM_ADMIN"));
        Mockito.when(accounts.roles(APP_ADMIN)).thenReturn(List.of("ROLE_ADMIN_APP"));
        Mockito.when(accounts.roles(NON_ADMIN)).thenReturn(List.of("ROLE_USER"));
        Mockito.when(accounts.roles(AUDITOR)).thenReturn(List.of("ROLE_ADMIN_AUDIT"));
        MfaService mfa = Mockito.mock(MfaService.class);
        Mockito.when(mfa.recent(Mockito.any())).thenReturn(true);
        var registration = new ClientRegistrationService(clients, false);
        service = new ClientAdminService(clients, jdbc, tx, accounts, new AdminAuditService(jdbc, clock), mfa, registration, clock, env);
        previous = new PreviousClientSecretAuthenticationProvider(clients, jdbc, clock);
    }
    @BeforeEach void seed() {
        Flyway.configure().dataSource(jdbc.getDataSource()).cleanDisabled(false).load().clean();
        Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
        jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('client-test','1')");
        user(OPERATOR, "operator");
        user(APP_ADMIN, "app-admin");
        user(NON_ADMIN, "plain");
    }
    private void user(UUID id, String employee) {
        jdbc.update("""
                INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch)
                VALUES (?,?,?,'OPENLDAP','uid='||?::text,'Test','ACTIVE','client-test',1,5)
                """, id, employee, UUID.randomUUID(), employee);
    }
    private IdentityPrincipal principal(UUID user, List<String> roles) {
        return new IdentityPrincipal(user, 5, now.get(), roles, now.get(),
                IdentityPrincipal.Method.PASSWORD, now.get(), UUID.randomUUID());
    }
    private IdentityPrincipal operator() { return principal(OPERATOR, List.of("ROLE_SYSTEM_ADMIN")); }
    private ClientAdminService.Registration registration(String id, String kind) {
        return new ClientAdminService.Registration(id, "Test application", kind,
                List.of("https://app.example/callback"), List.of("https://app.example/"), Set.of("openid", "api.read"), null, "开通应用");
    }
    private RegisteredClient client(String id) { return clients.findByClientId(id); }
    private ResponseStatusException rejected(Runnable call) {
        try { call.run(); throw new AssertionError("Expected rejection"); }
        catch (ResponseStatusException e) { return e; }
    }
    private OAuth2ClientAuthenticationToken presented(String clientId, String secret) {
        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, secret, Map.of());
    }

    @Test void registerShowsTheSecretOnceAndStoresOnlyItsHash() {
        var issued = service.register(operator(), registration("crm", "CONFIDENTIAL"));
        assertTrue(issued.secret().matches("[A-Za-z0-9_-]{43}"), "generated secret must be 43 url-safe characters");
        assertNotNull(issued.id());
        RegisteredClient stored = client("crm");
        assertNotEquals(issued.secret(), stored.getClientSecret());
        assertTrue(PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(issued.secret(), stored.getClientSecret()));
        assertTrue(stored.getClientSettings().isRequireProofKey());
        assertEquals(Set.of("openid", "api.read"), stored.getScopes());
        var summaries = service.list();
        assertEquals(1, summaries.size());
        assertEquals("CONFIDENTIAL", summaries.get(0).kind());
        assertEquals("crm", summaries.get(0).clientId());
        Map<String, Object> audit = jdbc.queryForMap("SELECT detail->>'client_id' AS client_id, detail->>'kind' AS kind FROM auth_audit WHERE action='CLIENT_REGISTERED'");
        assertEquals("crm", audit.get("client_id"));
        assertEquals("CONFIDENTIAL", audit.get("kind"));
        // A public client gets no secret at all.
        assertNull(service.register(operator(), registration("mobile", "NATIVE")).secret());
        assertEquals("NATIVE", service.list().stream().filter(s -> s.clientId().equals("mobile")).findFirst().orElseThrow().kind());
    }

    @Test void rejectedWithoutRecentPasswordRecency() {
        // mfa.recent is mocked true; exercise the recent-password half of the privileged-write gate.
        IdentityPrincipal stale = new IdentityPrincipal(OPERATOR, 5, now.get().minusSeconds(1000), List.of("ROLE_SYSTEM_ADMIN"), now.get(),
                IdentityPrincipal.Method.PASSWORD, now.get().minusSeconds(1000), UUID.randomUUID());
        assertEquals(403, rejected(() -> service.register(stale, registration("crm", "CONFIDENTIAL"))).getStatusCode().value());
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM oauth2_registered_client", Integer.class));
    }

    @Test void registrationRejectsBadSpecificationsAndMissingAuthority() {
        IdentityPrincipal plain = principal(NON_ADMIN, List.of("ROLE_USER"));
        assertEquals(403, rejected(() -> service.register(plain, registration("crm", "CONFIDENTIAL"))).getStatusCode().value());
        service.register(operator(), registration("crm", "CONFIDENTIAL"));
        assertEquals(409, rejected(() -> service.register(operator(), registration("crm", "CONFIDENTIAL"))).getStatusCode().value());
        assertEquals(400, rejected(() -> service.register(operator(), registration("bad", "UNKNOWN"))).getStatusCode().value());
        assertEquals(400, rejected(() -> service.register(operator(), new ClientAdminService.Registration("weak", "Weak", "CONFIDENTIAL",
                List.of("http://app.example/cb"), List.of(), Set.of("openid"), null, "原因"))).getStatusCode().value());
        assertEquals(400, rejected(() -> service.register(operator(), new ClientAdminService.Registration("noscope", "No", "SPA",
                List.of("https://app.example/cb"), List.of(), Set.of("profile"), null, "原因"))).getStatusCode().value());
        assertEquals(400, rejected(() -> service.register(operator(), new ClientAdminService.Registration("noreason", "No", "SPA",
                List.of("https://app.example/cb"), List.of(), Set.of("openid"), null, " "))).getStatusCode().value());
        assertEquals(400, rejected(() -> service.register(operator(), new ClientAdminService.Registration("ab", "Short", "SPA",
                List.of("https://app.example/cb"), List.of(), Set.of("openid"), null, "原因"))).getStatusCode().value());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM oauth2_registered_client", Integer.class));
    }

    @Test void appAdminMayManageApplicationsAndTheActionIsAudited() {
        IdentityPrincipal appAdmin = principal(APP_ADMIN, List.of("ROLE_ADMIN_APP"));
        service.register(appAdmin, registration("hrm", "NATIVE"));
        assertEquals(400, rejected(() -> service.rotate(appAdmin, "hrm", "公共客户端无密钥", "rotate-unit-key-0009")).getStatusCode().value());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action='CLIENT_REGISTERED'", Integer.class));
    }

    @Test void rotationKeepsThePreviousSecretUntilTheWindowCloses() {
        String first = service.register(operator(), registration("crm", "CONFIDENTIAL")).secret();
        var rotated = service.rotate(operator(), "crm", "季度轮换", "rotate-unit-key-0001");
        assertNotEquals(first, rotated.secret());
        assertEquals(now.get().plus(overlap), rotated.previousSecretValidUntil());
        // The new secret is the current one; the previous secret authenticates only via the fallback.
        assertTrue(PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(rotated.secret(), client("crm").getClientSecret()));
        assertEquals("crm", ((OAuth2ClientAuthenticationToken) previous.authenticate(presented("crm", first))).getRegisteredClient().getClientId());
        assertNull(previous.authenticate(presented("crm", rotated.secret())));
        now.updateAndGet(value -> value.plus(overlap).plusSeconds(1));
        assertNull(previous.authenticate(presented("crm", first)), "expired previous secret must not authenticate");
        // The current secret is validated by the built-in provider, never by this fallback.
        assertNull(previous.authenticate(presented("crm", rotated.secret())));
        // History stores a hash only, never the raw secret.
        String stored = jdbc.queryForObject("SELECT secret_hash FROM oauth_client_secret_previous WHERE client_id='crm'", String.class);
        assertNotEquals(first, stored);
        assertTrue(stored.startsWith("{"));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action='CLIENT_SECRET_ROTATED' AND detail->>'client_id'='crm'", Integer.class));
    }

    @Test void rotationIsIdempotentPerKeyAndRejectsPublicClients() {
        service.register(operator(), registration("crm", "CONFIDENTIAL"));
        String current = client("crm").getClientSecret();
        service.rotate(operator(), "crm", "第一次", "rotate-unit-key-0002");
        assertEquals(409, rejected(() -> service.rotate(operator(), "crm", "第一次", "rotate-unit-key-0002")).getStatusCode().value());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM admin_client_action WHERE action='ROTATE'", Integer.class));
        assertEquals(404, rejected(() -> service.rotate(operator(), "missing", "原因", "rotate-unit-key-0003")).getStatusCode().value());
        service.register(operator(), registration("spa", "SPA"));
        assertEquals(400, rejected(() -> service.rotate(operator(), "spa", "原因", "rotate-unit-key-0004")).getStatusCode().value());
        assertEquals(400, rejected(() -> service.rotate(operator(), "crm", "原因", "short")).getStatusCode().value());
        assertNotEquals(current, client("crm").getClientSecret(), "the successful rotation updates the current hash");
    }

    @Test void editChangesCallbacksScopesAndNameWithValidation() {
        service.register(operator(), registration("crm", "CONFIDENTIAL"));
        var edited = new ClientAdminService.Registration("crm", "CRM 新名称",
                "CONFIDENTIAL", List.of("https://crm.example/cb2"), List.of("https://crm.example/bye"),
                Set.of("openid", "profile"), "https://crm.example/logout/backchannel", "调整回调");
        service.update(operator(), "crm", edited, edited.reason());
        RegisteredClient stored = client("crm");
        assertEquals("CRM 新名称", stored.getClientName());
        assertEquals(Set.of("https://crm.example/cb2"), stored.getRedirectUris());
        assertEquals(Set.of("https://crm.example/bye"), stored.getPostLogoutRedirectUris());
        assertEquals(Set.of("openid", "profile"), stored.getScopes());
        assertEquals("https://crm.example/logout/backchannel", stored.getClientSettings().getSetting("unipass.backchannel_logout_uri"));
        assertNotNull(stored.getClientSecret(), "editing keeps the current secret");
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action='CLIENT_UPDATED' AND detail->>'client_id'='crm'", Integer.class));
        // Kind is immutable, callbacks stay strict and the target must exist.
        assertEquals(400, rejected(() -> service.update(operator(), "crm", new ClientAdminService.Registration(
                "crm", "X", "SPA", List.of("https://crm.example/cb2"), List.of(), Set.of("openid"), null, "原因"), "原因")).getStatusCode().value());
        assertEquals(400, rejected(() -> service.update(operator(), "crm", new ClientAdminService.Registration(
                "crm", "X", "CONFIDENTIAL", List.of("http://crm.example/cb"), List.of(), Set.of("openid"), null, "原因"), "原因")).getStatusCode().value());
        assertEquals(400, rejected(() -> service.update(operator(), "crm", new ClientAdminService.Registration(
                "crm", "X", "CONFIDENTIAL", List.of("https://crm.example/cb2"), List.of(), Set.of("profile"), null, "原因"), "原因")).getStatusCode().value());
        assertEquals(400, rejected(() -> service.update(operator(), "crm", new ClientAdminService.Registration(
                "other", "X", "CONFIDENTIAL", List.of("https://crm.example/cb2"), List.of(), Set.of("openid"), null, "原因"), "原因")).getStatusCode().value());
        assertEquals(404, rejected(() -> service.update(operator(), "missing", new ClientAdminService.Registration(
                "missing", "X", "CONFIDENTIAL", List.of("https://crm.example/cb2"), List.of(), Set.of("openid"), null, "原因"), "原因")).getStatusCode().value());
        assertEquals(403, rejected(() -> service.update(principal(NON_ADMIN, List.of("ROLE_USER")), "crm", edited, "原因")).getStatusCode().value());
    }

    @Test void disableRevokesFamiliesBlocksProtocolEndpointsAndEnableRestores() throws Exception {
        service.register(operator(), registration("crm", "CONFIDENTIAL"));
        String crmId = jdbc.queryForObject("SELECT id FROM oauth2_registered_client WHERE client_id='crm'", String.class);
        jdbc.update("""
                INSERT INTO oauth2_authorization(id,registered_client_id,principal_name,authorization_grant_type,authorized_scopes,attributes)
                VALUES ('family-1',?,?,'authorization_code','openid','')
                """, crmId, OPERATOR.toString());
        service.setEnabled(operator(), "crm", false, "疑似泄露", "disable-unit-key-001", "203.0.113.9");
        assertFalse(service.list().get(0).enabled());
        assertEquals("203.0.113.9", jdbc.queryForObject(
                "SELECT source_ip FROM auth_audit WHERE action='CLIENT_DISABLED'", String.class));
        assertTrue(jdbc.queryForObject("SELECT revoked FROM oauth2_authorization WHERE id='family-1'", Boolean.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action='CLIENT_DISABLED'", Integer.class));
        // Protocol endpoints are blocked before any authorization-server provider runs.
        var request = new org.springframework.mock.web.MockHttpServletRequest("POST", "/oauth/token");
        request.setParameter("client_id", "crm");
        var response = new org.springframework.mock.web.MockHttpServletResponse();
        var invoked = new java.util.concurrent.atomic.AtomicBoolean();
        new ClientStatusFilter(jdbc).doFilterInternal(request, response, (req, res) -> invoked.set(true));
        assertEquals(401, response.getStatus());
        assertTrue(response.getContentAsString().contains("invalid_client"));
        assertFalse(invoked.get());
        // A different, still-enabled client passes through untouched.
        service.register(operator(), registration("hrm", "CONFIDENTIAL"));
        var allowed = new org.springframework.mock.web.MockHttpServletRequest("POST", "/oauth/token");
        allowed.setParameter("client_id", "hrm");
        var allowedResponse = new org.springframework.mock.web.MockHttpServletResponse();
        var allowedInvoked = new java.util.concurrent.atomic.AtomicBoolean();
        new ClientStatusFilter(jdbc).doFilterInternal(allowed, allowedResponse, (req, res) -> allowedInvoked.set(true));
        assertTrue(allowedInvoked.get());
        // Replaying the same key is idempotent: no duplicate audit, no re-applied change.
        assertDoesNotThrow(() -> service.setEnabled(operator(), "crm", false, "疑似泄露", "disable-unit-key-001"));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action='CLIENT_DISABLED'", Integer.class));
        assertFalse(service.list().stream().filter(item -> item.clientId().equals("crm")).findFirst().orElseThrow().enabled());
        service.setEnabled(operator(), "crm", true, "误报解除", "enable-unit-key-0001");
        assertTrue(service.list().stream().filter(item -> item.clientId().equals("crm")).findFirst().orElseThrow().enabled());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action='CLIENT_ENABLED'", Integer.class));
        assertEquals(404, rejected(() -> service.setEnabled(operator(), "missing", false, "不存在", "state-unit-key-0001")).getStatusCode().value());
        assertEquals(400, rejected(() -> service.setEnabled(operator(), "crm", false, "坏键", "short")).getStatusCode().value());
    }

    @Test void deleteSoftRemovesTheClientBlocksRevivalAndIsIdempotent() {
        service.register(operator(), registration("crm", "CONFIDENTIAL"));
        String crmId = jdbc.queryForObject("SELECT id FROM oauth2_registered_client WHERE client_id='crm'", String.class);
        jdbc.update("""
                INSERT INTO oauth2_authorization(id,registered_client_id,principal_name,authorization_grant_type,authorized_scopes,attributes)
                VALUES ('family-del',?,?,'authorization_code','openid','')
                """, crmId, OPERATOR.toString());
        service.delete(operator(), "crm", "不再需要", "delete-unit-key-0001", "203.0.113.10");
        // The management list no longer exposes the tombstone.
        assertTrue(service.list().stream().noneMatch(s -> s.clientId().equals("crm")));
        // The status row records the tombstone while remaining disabled.
        assertTrue(jdbc.queryForObject("SELECT disabled FROM oauth_client_status WHERE client_id='crm'", Boolean.class));
        assertNotNull(jdbc.queryForObject("SELECT deleted_at FROM oauth_client_status WHERE client_id='crm'", Timestamp.class));
        assertEquals("203.0.113.10", jdbc.queryForObject("SELECT source_ip FROM auth_audit WHERE action='CLIENT_DELETED'", String.class));
        // The real authorization family is revoked with the registration id.
        assertTrue(jdbc.queryForObject("SELECT revoked FROM oauth2_authorization WHERE id='family-del'", Boolean.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action='CLIENT_DELETED'", Integer.class));
        // Same key + same reason replays successfully without re-auditing or re-recording the action.
        assertDoesNotThrow(() -> service.delete(operator(), "crm", "不再需要", "delete-unit-key-0001"));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM auth_audit WHERE action='CLIENT_DELETED'", Integer.class));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM admin_client_action WHERE action='DELETE'", Integer.class));
        // Same key + different reason conflicts; a brand-new key on a deleted client also conflicts.
        assertEquals(409, rejected(() -> service.delete(operator(), "crm", "另一个原因", "delete-unit-key-0001")).getStatusCode().value());
        assertEquals(409, rejected(() -> service.delete(operator(), "crm", "新键删除", "delete-unit-key-0002")).getStatusCode().value());
        // Deletion wins over enabled: enable and disable are both refused.
        assertEquals(409, rejected(() -> service.setEnabled(operator(), "crm", true, "复活", "enable-del-000001")).getStatusCode().value());
        assertEquals(409, rejected(() -> service.setEnabled(operator(), "crm", false, "再停用", "disable-del-0001")).getStatusCode().value());
        // An unrelated client is unaffected.
        service.register(operator(), registration("hrm", "CONFIDENTIAL"));
        assertEquals(1, service.list().stream().filter(s -> s.clientId().equals("hrm")).count());
        // Unknown client, short key, blank reason and missing authority are all rejected.
        assertEquals(404, rejected(() -> service.delete(operator(), "missing", "原因", "delete-missing-0001")).getStatusCode().value());
        assertEquals(400, rejected(() -> service.delete(operator(), "crm", "原因", "short")).getStatusCode().value());
        assertEquals(400, rejected(() -> service.delete(operator(), "crm", " ", "delete-empty-reason")).getStatusCode().value());
        assertEquals(403, rejected(() -> service.delete(principal(NON_ADMIN, List.of("ROLE_USER")), "crm", "原因", "delete-noauth-0001")).getStatusCode().value());
        // The registration row is preserved (no physical deletion).
        assertNotNull(jdbc.queryForObject("SELECT id FROM oauth2_registered_client WHERE client_id='crm'", String.class));
    }

    @Test void auditorReadsAuditButCannotChangeRolesOrClients() {
        var console = new AdminConsoleService(jdbc, tx, accounts, new AdminAuditService(jdbc, java.time.Clock.systemUTC()), null, java.time.Clock.systemUTC());
        IdentityPrincipal auditor = principal(AUDITOR, List.of("ROLE_ADMIN_AUDIT"));
        assertDoesNotThrow(() -> console.requireAuditor(auditor));
        assertEquals(403, rejected(() -> console.requireConsole(auditor)).getStatusCode().value());
        assertEquals(403, rejected(() -> service.register(auditor, registration("nope", "SPA"))).getStatusCode().value());
        IdentityPrincipal appAdmin = principal(APP_ADMIN, List.of("ROLE_ADMIN_APP"));
        assertEquals(403, rejected(() -> console.requireAuditor(appAdmin)).getStatusCode().value());
        assertTrue(AdminConsoleService.ASSIGNABLE.contains("ROLE_ADMIN_AUDIT"));
    }

    @Test void expiredPreviousSecretsAreIgnoredAndMalformedHashesFailClosed() {
        service.register(operator(), registration("crm", "CONFIDENTIAL"));
        String first = client("crm").getClientSecret();
        jdbc.update("INSERT INTO oauth_client_secret_previous(client_id,secret_hash,valid_until) VALUES ('crm',?,?)",
                "{bcrypt}$2a$10$abcdefghijklmnopqrstuv", java.sql.Timestamp.from(now.get().minusSeconds(1)));
        assertNull(previous.authenticate(presented("crm", "some-secret-value-that-does-not-matter")));
        assertNull(previous.authenticate(presented("unknown", "secret")));
        assertEquals(first, client("crm").getClientSecret());
    }

    @AfterAll void stop() throws Exception { if (pg != null) pg.close(); }
}
