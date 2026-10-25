package com.unipass.server;

import com.fasterxml.jackson.databind.*;
import com.unipass.directory.*;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.annotation.DirtiesContext;

import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * HTTP/security integration tests for the T8 application (client) management API.
 * These exercise the full security chain (form login, MFA step-up, CSRF, role
 * checks, recent-password/MFA recency and client-secret authentication) that the
 * service-level {@link ClientAdminIT} cannot reach. Mirrors the OidcFlowIT
 * embedded PostgreSQL + Redis fixture so the assertions run against the real
 * filter chain and authorization server.
 */
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT, classes={UniPassApplication.class, OidcFlowIT.TestDirectory.class})
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode=DirtiesContext.ClassMode.AFTER_CLASS)
class ClientManagementHttpIT {
    private static EmbeddedPostgres postgres;
    private static Process redis;
    private static Path signingStore;
    private static int redisPort;
    private static String redisPassword;
    private static final String ISSUER = "http://localhost:9999", CALLBACK = "https://rp.example.test/callback";
    private static final String OLD = "Qx!7vN2$pk";
    @LocalServerPort int port;
    @Autowired JdbcTemplate jdbc;
    @Autowired RegisteredClientRepository clients;
    @Autowired OidcFlowIT.FakeDirectory directory;
    @Autowired PasswordReauthentication reauthentication;
    @Autowired DigestAuthorizationService authorizations;
    @Autowired MfaService mfa;
    @Autowired AccountState accounts;
    @Autowired LoginSessions loginSessions;
    @Autowired MfaKeyService factorKeys;
    @Autowired MfaLifecycleService factors;
    @Autowired EmailRecoveryService recovery;
    @Autowired RecoveryMailWorker mailWorker;
    @Autowired OidcFlowIT.TestMail mail;
    @Autowired org.springframework.data.redis.core.StringRedisTemplate redisTemplate;
    @Autowired org.springframework.transaction.support.TransactionTemplate transactions;
    @Autowired RedisSecurityState securityState;
    @Autowired FeishuFixture feishuRemote;
    @Autowired com.unipass.password.PasswordChangeService passwords;
    private final ObjectMapper json = new ObjectMapper();
    private UUID user;

    @DynamicPropertySource static void properties(DynamicPropertyRegistry props) throws Exception {
        Path root = Files.createDirectories(Path.of("target", "client-management-test")).toAbsolutePath();
        System.setProperty("ot.epg.working-dir", Files.createDirectories(root.resolve("postgres")).toString());
        postgres = EmbeddedPostgres.builder().setPort(0).setServerConfig("listen_addresses", "127.0.0.1").start();
        try (ServerSocket socket = new ServerSocket(0)) { redisPort = socket.getLocalPort(); }
        redisPassword = UUID.randomUUID().toString();
        String executable = System.getProperty("test.redis.executable", System.getenv().getOrDefault("UNIPASS_TEST_REDIS_EXECUTABLE", "redis-server"));
        redis = new ProcessBuilder(executable, "--bind", "127.0.0.1", "--port", Integer.toString(redisPort), "--save", "", "--appendonly", "no",
                "--requirepass", redisPassword, "--dir", root.toString().replace('\\','/'))
                .redirectErrorStream(true).redirectOutput(root.resolve("redis.log").toFile()).start();
        Process ownedRedis = redis;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> { if (ownedRedis.isAlive()) ownedRedis.destroy(); }));
        boolean ready = false;
        for (int i = 0; i < 100; i++) {
            if (!redis.isAlive()) throw new IllegalStateException("Test Redis exited: " + Files.readString(root.resolve("redis.log")));
            try (Socket socket = new Socket()) { socket.connect(new InetSocketAddress("127.0.0.1", redisPort), 100); ready = true; break; }
            catch (IOException e) { Thread.sleep(50); }
        }
        if (!ready) throw new IllegalStateException("Test Redis startup timed out");
        signingStore = root.resolve("signing.p12");
        if (!Files.exists(signingStore)) {
            String keytool = Path.of(System.getProperty("java.home"), "bin", windows() ? "keytool.exe" : "keytool").toString();
            Process key = new ProcessBuilder(keytool, "-genkeypair", "-alias", "current", "-keyalg", "RSA", "-keysize", "2048", "-validity", "30",
                    "-dname", "CN=UniPass Test", "-storetype", "PKCS12", "-keystore", signingStore.toString(), "-storepass", "test-only-password", "-noprompt")
                    .redirectErrorStream(true).redirectOutput(root.resolve("keytool.log").toFile()).start();
            if (!key.waitFor(20, TimeUnit.SECONDS) || key.exitValue() != 0) throw new IllegalStateException("Test signing-key creation failed");
        }
        props.add("spring.datasource.url", () -> postgres.getJdbcUrl("postgres", "postgres"));
        props.add("spring.datasource.username", () -> "postgres"); props.add("spring.datasource.password", () -> "test");
        props.add("spring.data.redis.host", () -> "127.0.0.1"); props.add("spring.data.redis.port", () -> redisPort);
        props.add("spring.data.redis.password", () -> redisPassword);
        props.add("unipass.issuer", () -> ISSUER); props.add("unipass.local-http", () -> true); props.add("unipass.directory.enabled", () -> false);
        props.add("server.address", () -> "127.0.0.1");
        props.add("unipass.signing.store", () -> signingStore.toString()); props.add("unipass.signing.password", () -> "test-only-password"); props.add("unipass.signing.alias", () -> "current");
        props.add("unipass.password.history-verified", () -> true);
        props.add("unipass.mfa.key", () -> Base64.getEncoder().encodeToString(new byte[32]));
        props.add("unipass.mfa.keys-json", () -> "{\"next\":\"" + nextFactorKey() + "\"}");
        props.add("unipass.jobs.enabled", () -> false);
        props.add("unipass.feishu.enabled", () -> true);
        props.add("UNIPASS_FEISHU_APP_ID", () -> FeishuFixture.APP);
        props.add("UNIPASS_FEISHU_TENANT_KEY", () -> FeishuFixture.TENANT);
        props.add("UNIPASS_FEISHU_APP_SECRET", () -> FeishuFixture.SECRET);
        props.add("UNIPASS_FEISHU_CALLBACK", () -> "https://localhost:9999/api/connector/feishu/callback");
        props.add("unipass.password.reset-history-verified", () -> true);
    }

    @BeforeEach void seed() {
        factorKeys.activate("legacy", "test:fixture", "test:reset");
        jdbc.execute("TRUNCATE oauth2_authorization CASCADE"); jdbc.execute("TRUNCATE import_source CASCADE");
        jdbc.execute("TRUNCATE oauth2_registered_client, oauth_client_status, oauth_client_secret_previous, admin_client_action, auth_audit, oidc_logout_task CASCADE");
        jdbc.execute("TRUNCATE feishu_flow,feishu_code_use"); feishuRemote.reset();
        user = UUID.randomUUID(); directory.password = OLD; directory.afterVerify = () -> {}; mail.reset();
        var resetKeys = redisTemplate.keys("unipass:reset:*"); if (resetKeys != null && !resetKeys.isEmpty()) redisTemplate.delete(resetKeys);
        jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('hr','1')");
        jdbc.update("INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version) VALUES (?,'E001',?,'OPENLDAP','uid=one,dc=example','Test','ACTIVE','hr',1)", user, user);
        jdbc.update("DELETE FROM iam_user_role WHERE user_id=?", user);
    }

    private HttpClient browser() { return HttpClient.newBuilder().cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).followRedirects(HttpClient.Redirect.NEVER).build(); }
    private URI uri(String path) { return URI.create("http://localhost:" + port + path); }
    private HttpResponse<String> get(HttpClient client, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(path)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> post(HttpClient client, String path, Map<String, String> form, String clientId) throws Exception {
        String body = form.entrySet().stream().map(e -> enc(e.getKey()) + "=" + enc(e.getValue())).collect(java.util.stream.Collectors.joining("&"));
        var request = HttpRequest.newBuilder(uri(path)).header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body));
        if (clientId == null) request.header("Origin", ISSUER);
        if (clientId != null && !clientId.equals("native")) request.header("Authorization", "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + OLD + "-" + clientId).getBytes(StandardCharsets.UTF_8)));
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
    private String authorize(String client, String verifier) throws Exception {
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        return "/oauth/authorize?response_type=code&client_id=" + client + "&redirect_uri=" + enc(CALLBACK) + "&scope=openid%20profile%20api.read&state=test-state-123&nonce=test-nonce-123&code_challenge_method=S256&code_challenge=" + challenge;
    }
    private String code(HttpClient client, String clientId, String verifier) throws Exception {
        String path = authorize(clientId, verifier); var first = get(client, path);
        if (first.statusCode() != 302 || !first.headers().firstValue("Location").orElse("").startsWith(CALLBACK)) {
            login(client);
            first = get(client, path);
        }
        assertEquals(302, first.statusCode(), first.body()); String location = first.headers().firstValue("Location").orElseThrow();
        assertTrue(location.startsWith(CALLBACK), location);
        for (String pair : URI.create(location).getRawQuery().split("&")) if (pair.startsWith("code=")) return URLDecoder.decode(pair.substring(5), StandardCharsets.UTF_8);
        throw new AssertionError(location);
    }
    private void login(HttpClient client) throws Exception { login(client, "E001"); }
    private void login(HttpClient client, String employee) throws Exception {
        var proof = get(client, "/api/public/csrf"); assertEquals(200, proof.statusCode(), proof.body()); var csrf = json.readTree(proof.body());
        var response = post(client, "/login", Map.of("username", employee, "password", directory.password, csrf.get("parameter_name").asText(), csrf.get("token").asText()), null);
        assertEquals(302, response.statusCode(), response.body());
    }
    private HttpResponse<String> postJson(HttpClient client, String path, Object value) throws Exception {
        var csrfResponse = get(client, "/api/session/csrf"); assertEquals(200, csrfResponse.statusCode(), csrfResponse.body());
        var csrf = json.readTree(csrfResponse.body());
        return client.send(HttpRequest.newBuilder(uri(path)).header("Content-Type", "application/json").header("Origin", ISSUER).header(csrf.get("header_name").asText(), csrf.get("token").asText())
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(value))).build(), HttpResponse.BodyHandlers.ofString());
    }
    /** Authenticated admin write with CSRF + Origin and an optional Idempotency-Key header. */
    private HttpResponse<String> adminJson(HttpClient client, String path, Object value, String key) throws Exception {
        var csrfResponse = get(client, "/api/public/csrf"); assertEquals(200, csrfResponse.statusCode(), csrfResponse.body());
        var csrf = json.readTree(csrfResponse.body());
        var request = HttpRequest.newBuilder(uri(path)).header("Content-Type", "application/json").header("Origin", ISSUER)
                .header(csrf.get("header_name").asText(), csrf.get("token").asText());
        if (key != null) request.header("Idempotency-Key", key);
        return client.send(request.POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(value))).build(), HttpResponse.BodyHandlers.ofString());
    }
    private String otp(byte[] secret, Instant instant) throws Exception {
        return new com.eatthepath.otp.TimeBasedOneTimePasswordGenerator().generateOneTimePasswordString(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA1"), instant, Locale.ROOT);
    }
    private byte[] seedFactor() { return seedFactor(user); }
    private byte[] seedFactor(UUID identity) {
        byte[] secret = new byte[20]; new java.security.SecureRandom().nextBytes(secret);
        var cipher = new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]));
        jdbc.update("INSERT INTO mfa_totp(user_id,secret_cipher,enabled) VALUES (?,?,true) " +
                "ON CONFLICT (user_id) DO UPDATE SET secret_cipher=excluded.secret_cipher, enabled=true, pending_expires_at=NULL, last_used_step=-1, failed_attempts=0, locked_until=NULL",
                identity, cipher.encrypt(identity, secret)); return secret;
    }
    private void stepUp(HttpClient client, byte[] secret, Instant at) throws Exception {
        String context = json.readTree(postJson(client, "/api/mfa/context", Map.of()).body()).get("context").asText();
        String challenge = json.readTree(postJson(client, "/api/mfa/challenges", Map.of("context", context)).body()).get("challenge").asText();
        var result = postJson(client, "/api/mfa/verify", Map.of("context", context, "challenge", challenge, "code", otp(secret, at)));
        assertEquals(200, result.statusCode(), result.body());
    }
    private static String nextFactorKey() { byte[] raw = new byte[32]; Arrays.fill(raw, (byte) 1); return Base64.getEncoder().encodeToString(raw); }
    private static boolean windows() { return System.getProperty("os.name").startsWith("Windows"); }
    private static String enc(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }

    /** A logged-in administrator session (recent password + recent MFA) carrying the given roles. */
    private HttpClient administrator(String... roles) throws Exception {
        for (String role : roles) jdbc.update("INSERT INTO iam_user_role(user_id,role) VALUES (?,?)", user, role);
        byte[] secret = seedFactor();
        HttpClient browser = browser();
        login(browser);
        stepUp(browser, secret, Instant.now());
        return browser;
    }

    private Map<String, Object> confidentialBody(String clientId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("clientId", clientId);
        body.put("name", "App " + clientId);
        body.put("kind", "CONFIDENTIAL");
        body.put("redirectUris", List.of(CALLBACK));
        body.put("logoutRedirectUris", List.of("https://rp.example.test/"));
        body.put("scopes", List.of("openid", "profile", "api.read"));
        body.put("reason", "开通应用");
        return body;
    }
    private Map<String, Object> publicBody(String clientId, String kind) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("clientId", clientId);
        body.put("name", "App " + clientId);
        body.put("kind", kind);
        body.put("redirectUris", List.of(CALLBACK));
        body.put("logoutRedirectUris", List.of("https://rp.example.test/"));
        body.put("scopes", List.of("openid", "api.read"));
        body.put("reason", "开通应用");
        return body;
    }

    /** Register a confidential client; returns the once-shown cleartext secret. */
    private String registerConfidential(HttpClient admin, String clientId) throws Exception {
        var resp = adminJson(admin, "/api/admin/console/clients", confidentialBody(clientId), null);
        assertTrue(resp.statusCode() >= 200 && resp.statusCode() < 300, resp.body());
        var node = json.readTree(resp.body());
        assertEquals(clientId, node.get("clientId").asText());
        assertTrue(node.get("secret").asText().matches("[A-Za-z0-9_-]{43}"));
        return node.get("secret").asText();
    }
    private String rotateSecret(HttpClient admin, String clientId) throws Exception {
        var resp = adminJson(admin, "/api/admin/console/clients/" + clientId + "/rotate",
                Map.of("reason", "季度轮换"), UUID.randomUUID().toString());
        assertTrue(resp.statusCode() >= 200 && resp.statusCode() < 300, resp.body());
        return json.readTree(resp.body()).get("secret").asText();
    }
    private HttpResponse<String> tokenExchange(String clientId, String secret, String code, String verifier) throws Exception {
        String body = "grant_type=authorization_code&code=" + enc(code) + "&redirect_uri=" + enc(CALLBACK) + "&code_verifier=" + enc(verifier);
        String basic = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
        return browser().send(HttpRequest.newBuilder(uri("/oauth/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + basic)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
    private int tokenStatus(HttpClient admin, String clientId, String secret) throws Exception {
        String verifier = "v".repeat(64);
        String authCode = code(admin, clientId, verifier);
        return tokenExchange(clientId, secret, authCode, verifier).statusCode();
    }
    private JsonNode tokensFor(HttpClient admin, String clientId, String secret) throws Exception {
        String verifier = "v".repeat(64);
        String authCode = code(admin, clientId, verifier);
        var resp = tokenExchange(clientId, secret, authCode, verifier);
        assertEquals(200, resp.statusCode(), resp.body());
        return json.readTree(resp.body());
    }
    private int authorizeStatus(HttpClient client, String clientId, String verifier) throws Exception {
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        String path = "/oauth/authorize?response_type=code&client_id=" + clientId + "&redirect_uri=" + enc(CALLBACK) + "&scope=openid%20profile%20api.read&state=test-state-123&nonce=test-nonce-123&code_challenge_method=S256&code_challenge=" + challenge;
        return get(client, path).statusCode();
    }
    private int introspectStatus(HttpClient client, String clientId, String secret) throws Exception {
        String basic = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
        var resp = client.send(HttpRequest.newBuilder(uri("/oauth/introspect"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + basic)
                .POST(HttpRequest.BodyPublishers.ofString("token=dummy")).build(), HttpResponse.BodyHandlers.ofString());
        return resp.statusCode();
    }
    private int refreshStatus(String clientId, String refreshToken) throws Exception {
        return post(browser(), "/oauth/token", Map.of("grant_type", "refresh_token", "refresh_token", refreshToken, "client_id", clientId), clientId).statusCode();
    }

    @Test void anonymousAndPlainUserCannotReadOrWriteClients() throws Exception {
        HttpClient anon = browser();
        assertEquals(401, get(anon, "/api/admin/console/clients").statusCode());
        assertEquals(401, adminJson(anon, "/api/admin/console/clients", confidentialBody("crm"), null).statusCode());
        HttpClient plain = browser();
        login(plain);
        assertEquals(403, get(plain, "/api/admin/console/clients").statusCode());
        assertEquals(403, adminJson(plain, "/api/admin/console/clients", confidentialBody("crm"), null).statusCode());
    }

    @Test void readOnlyAuditorAndUserOperatorCannotChangeClients() throws Exception {
        HttpClient auditor = administrator("ROLE_ADMIN_AUDIT");
        assertEquals(403, get(auditor, "/api/admin/console/clients").statusCode());
        assertEquals(403, adminJson(auditor, "/api/admin/console/clients", confidentialBody("crm"), null).statusCode());
        HttpClient operator = administrator("ROLE_USER_OPERATOR");
        assertEquals(403, adminJson(operator, "/api/admin/console/clients", confidentialBody("crm"), null).statusCode());
    }

    @Test void appAdminAndSystemAdminMayManageApplications() throws Exception {
        HttpClient appAdmin = administrator("ROLE_ADMIN_APP");
        String secret = registerConfidential(appAdmin, "crm");
        assertNotNull(secret);
        HttpClient sysAdmin = administrator("ROLE_SYSTEM_ADMIN");
        String other = registerConfidential(sysAdmin, "hrm");
        assertNotNull(other);
        // The plain list is readable by an application administrator and contains no cleartext secret.
        var list = get(appAdmin, "/api/admin/console/clients");
        assertEquals(200, list.statusCode());
        JsonNode arr = json.readTree(list.body());
        assertTrue(arr.size() >= 2);
        for (JsonNode entry : arr) assertFalse(entry.has("secret"), entry.toString());
    }

    @Test void writeWithoutRecentMfaIsRejected() throws Exception {
        // Holder of the application-admin role, but logged in without stepping up MFA: the
        // recent-password/MFA gate must refuse the privileged write with 403 (not a role error).
        HttpClient appAdminNoMfa = browser();
        jdbc.update("INSERT INTO iam_user_role(user_id,role) VALUES (?,?)", user, "ROLE_ADMIN_APP");
        login(appAdminNoMfa);
        assertEquals(403, adminJson(appAdminNoMfa, "/api/admin/console/clients", confidentialBody("crm"), null).statusCode());
    }

    @Test void secretIsShownOnceAndNeverReturnedInListOrAudit() throws Exception {
        HttpClient admin = administrator("ROLE_SYSTEM_ADMIN");
        String secret = registerConfidential(admin, "crm");
        // List and detail never echo the cleartext or a hash.
        var list = get(admin, "/api/admin/console/clients");
        assertFalse(list.body().contains(secret));
        String detail = jdbc.queryForObject("SELECT detail FROM auth_audit WHERE action='CLIENT_REGISTERED' AND detail->>'client_id'=?", String.class, "crm");
        assertNotNull(detail);
        assertFalse(detail.contains(secret));
        assertFalse(detail.contains("{bcrypt}"));
        assertFalse(detail.contains("{noop}"));
        // Replay of the same client id is a conflict, not a second exposure.
        assertEquals(409, adminJson(admin, "/api/admin/console/clients", confidentialBody("crm"), null).statusCode());
        var listAfter = get(admin, "/api/admin/console/clients");
        assertFalse(listAfter.body().contains(secret));
    }

    @Test void rotationIsIdempotentPerKeyAndPublicClientsHaveNoSecret() throws Exception {
        HttpClient admin = administrator("ROLE_SYSTEM_ADMIN");
        String s1 = registerConfidential(admin, "crm");
        String s2 = rotateSecret(admin, "crm");
        assertNotEquals(s1, s2);
        // Same idempotency key replays to a conflict and does not re-expose a secret.
        var first = adminJson(admin, "/api/admin/console/clients/crm/rotate", Map.of("reason", "季度轮换"), "rotate-idem-key-0001");
        assertEquals(200, first.statusCode(), first.body());
        var second = adminJson(admin, "/api/admin/console/clients/crm/rotate", Map.of("reason", "季度轮换"), "rotate-idem-key-0001");
        assertEquals(409, second.statusCode(), second.body());
        assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM admin_client_action WHERE action='ROTATE' AND client_id='crm'", Integer.class));
        // Public clients cannot gain a secret through registration or rotation.
        var spa = administrator("ROLE_ADMIN_APP");
        var spaResp = adminJson(spa, "/api/admin/console/clients", publicBody("spa", "SPA"), null);
        assertTrue(spaResp.statusCode() >= 200 && spaResp.statusCode() < 300, spaResp.body());
        JsonNode publicIssued = json.readTree(spaResp.body());
        assertTrue(publicIssued.get("secret") == null || publicIssued.get("secret").isNull(),
                "public client must not carry a cleartext secret (field missing or explicit null acceptable): " + publicIssued);
        assertEquals(400, adminJson(spa, "/api/admin/console/clients/spa/rotate", Map.of("reason", "原因"), UUID.randomUUID().toString()).statusCode());
    }

    @Test void dualSecretWindowAcceptsBothUntilExpiryThenBlocksOld() throws Exception {
        HttpClient admin = administrator("ROLE_SYSTEM_ADMIN");
        String s1 = registerConfidential(admin, "crm");
        assertEquals(200, tokenStatus(admin, "crm", s1));
        String s2 = rotateSecret(admin, "crm");
        assertNotEquals(s1, s2);
        // Within the overlap window both the current and the previous secret authenticate at /oauth/token.
        assertEquals(200, tokenStatus(admin, "crm", s1));
        assertEquals(200, tokenStatus(admin, "crm", s2));
        // Close the window: the previous secret is immediately rejected, the current still works.
        jdbc.update("UPDATE oauth_client_secret_previous SET valid_until = now() - interval '1 second' WHERE client_id='crm'");
        assertEquals(401, tokenStatus(admin, "crm", s1));
        assertEquals(200, tokenStatus(admin, "crm", s2));
        // A further rotation cannot restore the earlier (s1) secret; only the immediately-previous (s2) remains.
        String s3 = rotateSecret(admin, "crm");
        assertEquals(401, tokenStatus(admin, "crm", s1));
        assertEquals(200, tokenStatus(admin, "crm", s2));
        assertEquals(200, tokenStatus(admin, "crm", s3));
    }

    @Test void disableBlocksProtocolEndpointsRevokesAuthorizationAndLeavesOthersUntouched() throws Exception {
        HttpClient admin = administrator("ROLE_SYSTEM_ADMIN");
        String sCrm = registerConfidential(admin, "crm");
        String sHrm = registerConfidential(admin, "hrm");
        JsonNode crmTokens = tokensFor(admin, "crm", sCrm);
        String crmRefresh = crmTokens.get("refresh_token").asText();
        assertEquals(200, tokenStatus(admin, "hrm", sHrm));
        // Seed an authorization family for crm (using its real registration id) so revocation is observable.
        String crmId = jdbc.queryForObject("SELECT id FROM oauth2_registered_client WHERE client_id='crm'", String.class);
        jdbc.update("INSERT INTO oauth2_authorization(id,registered_client_id,principal_name,authorization_grant_type,authorized_scopes,attributes) VALUES ('family-crm',?,?,'authorization_code','openid','')", crmId, user.toString());
        // Disable crm.
        var disable = adminJson(admin, "/api/admin/console/clients/crm/state", Map.of("enabled", false, "reason", "疑似泄露"), UUID.randomUUID().toString());
        assertEquals(204, disable.statusCode(), disable.body());
        // authorize/token/introspect/refresh for the disabled client all fail with 401 invalid_client.
        assertEquals(401, authorizeStatus(admin, "crm", "v".repeat(64)));
        assertEquals(401, introspectStatus(admin, "crm", sCrm));
        assertEquals(401, refreshStatus("crm", crmRefresh));
        // An unrelated, still-enabled client is unaffected.
        assertEquals(200, tokenStatus(admin, "hrm", sHrm));
        // Every authorization minted for crm (the real-flow token and the manual family) is revoked; none survive.
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM oauth2_authorization WHERE registered_client_id=? AND revoked=false", Integer.class, crmId));
        assertTrue(jdbc.queryForObject("SELECT revoked FROM oauth2_authorization WHERE id='family-crm'", Boolean.class));
        var enable = adminJson(admin, "/api/admin/console/clients/crm/state", Map.of("enabled", true, "reason", "误报解除"), UUID.randomUUID().toString());
        assertEquals(204, enable.statusCode(), enable.body());
        assertTrue(jdbc.queryForObject("SELECT revoked FROM oauth2_authorization WHERE id='family-crm'", Boolean.class));
    }

    @AfterAll void stop() throws Exception { if (redis != null && redis.isAlive()) redis.destroy(); if (postgres != null) postgres.close(); }
}
