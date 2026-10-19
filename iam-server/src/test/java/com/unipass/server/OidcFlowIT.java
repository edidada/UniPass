package com.unipass.server;

import com.fasterxml.jackson.databind.*;
import com.unipass.directory.*;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.*;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.test.context.*;
import org.springframework.test.annotation.DirtiesContext;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT, classes={UniPassApplication.class, OidcFlowIT.TestDirectory.class})
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode=DirtiesContext.ClassMode.AFTER_CLASS)
class OidcFlowIT {
    private static EmbeddedPostgres postgres;
    private static Process redis;
    private static Path signingStore;
    private static int redisPort;
    private static String redisPassword;
    private static final String ISSUER = "http://localhost:9999", CALLBACK = "https://rp.example.test/callback";
    private static final String OLD="Qx!7vN2$pk", NEW="Rz@8mP4#st", SECRET="test-client-only";
    @LocalServerPort int port;
    @Autowired JdbcTemplate jdbc;
    @Autowired RegisteredClientRepository clients;
    @Autowired FakeDirectory directory;
    @Autowired DigestAuthorizationService authorizations;
    @Autowired MfaService mfa;
    @Autowired EmailRecoveryService recovery;
    @Autowired RecoveryMailWorker mailWorker;
    @Autowired TestMail mail;
    @Autowired org.springframework.data.redis.core.StringRedisTemplate redisTemplate;
    @Autowired org.springframework.transaction.support.TransactionTemplate transactions;
    @Autowired RedisSecurityState securityState;
    @Autowired com.unipass.password.PasswordChangeService passwords;
    private final ObjectMapper json = new ObjectMapper();
    private UUID user;

    @DynamicPropertySource static void properties(DynamicPropertyRegistry props) throws Exception {
        Path root = Files.createDirectories(Path.of("target", "protocol-test")).toAbsolutePath();
        System.setProperty("ot.epg.working-dir", Files.createDirectories(root.resolve("postgres")).toString());
        postgres = EmbeddedPostgres.builder().setPort(0).setServerConfig("listen_addresses", "127.0.0.1").start();
        try (ServerSocket socket = new ServerSocket(0)) { redisPort = socket.getLocalPort(); }
        redisPassword = UUID.randomUUID().toString();
        String executable = System.getProperty("test.redis.executable", System.getenv().getOrDefault("UNIPASS_TEST_REDIS_EXECUTABLE", "redis-server"));
        redis = new ProcessBuilder(executable, "--bind", "127.0.0.1", "--port", Integer.toString(redisPort), "--save", "", "--appendonly", "no",
                "--requirepass", redisPassword, "--dir", root.toString().replace('\\','/'))
                .redirectErrorStream(true).redirectOutput(root.resolve("redis.log").toFile()).start();
        Process ownedRedis=redis;
        Runtime.getRuntime().addShutdownHook(new Thread(()->{if(ownedRedis.isAlive())ownedRedis.destroy();}));
        boolean ready = false;
        for (int i=0; i<100; i++) {
            if (!redis.isAlive()) throw new IllegalStateException("Test Redis exited: " + Files.readString(root.resolve("redis.log")));
            try (Socket socket = new Socket()) { socket.connect(new InetSocketAddress("127.0.0.1", redisPort), 100); ready=true; break; }
            catch (IOException e) { Thread.sleep(50); }
        }
        if (!ready) throw new IllegalStateException("Test Redis startup timed out");
        signingStore = root.resolve("signing.p12");
        if (!Files.exists(signingStore)) {
            String keytool = Path.of(System.getProperty("java.home"), "bin", windows() ? "keytool.exe" : "keytool").toString();
            Process key = new ProcessBuilder(keytool, "-genkeypair", "-alias", "current", "-keyalg", "RSA", "-keysize", "2048", "-validity", "30",
                    "-dname", "CN=UniPass Test", "-storetype", "PKCS12", "-keystore", signingStore.toString(), "-storepass", "test-only-password", "-noprompt")
                    .redirectErrorStream(true).redirectOutput(root.resolve("keytool.log").toFile()).start();
            if (!key.waitFor(20, TimeUnit.SECONDS) || key.exitValue()!=0) throw new IllegalStateException("Test signing-key creation failed");
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
        props.add("unipass.jobs.enabled", () -> false);
        props.add("unipass.password.reset-history-verified", () -> true);
    }
    @BeforeEach void seed() {
        jdbc.execute("TRUNCATE oauth2_authorization CASCADE"); jdbc.execute("TRUNCATE import_source CASCADE");
        user=UUID.randomUUID(); directory.password=OLD;mail.reset();
        var resetKeys=redisTemplate.keys("unipass:reset:*");if(resetKeys!=null && !resetKeys.isEmpty())redisTemplate.delete(resetKeys);
        jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('hr','1')");
        jdbc.update("INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version) VALUES (?,'E001',?,'OPENLDAP','uid=one,dc=example','Test','ACTIVE','hr',1)",user,user);
        for (String id : List.of("web", "native", "web-two")) if (clients.findByClientId(id)==null) {
            var builder=RegisteredClient.withId(UUID.randomUUID().toString()).clientId(id).redirectUri(CALLBACK).postLogoutRedirectUri("https://rp.example.test/")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .scope("openid").scope("profile").scope("api.read")
                    .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).setting("unipass.native", id.equals("native")).build())
                    .tokenSettings(TokenSettings.builder().authorizationCodeTimeToLive(Duration.ofSeconds(60)).accessTokenTimeToLive(Duration.ofHours(1)).refreshTokenTimeToLive(Duration.ofDays(30)).reuseRefreshTokens(false).build());
            if (id.equals("native")) builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
            else builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).clientSecret("{noop}"+SECRET+"-"+id);
            clients.save(builder.build());
        }
    }
    private HttpClient browser() { return HttpClient.newBuilder().cookieHandler(new CookieManager(null,CookiePolicy.ACCEPT_ALL)).followRedirects(HttpClient.Redirect.NEVER).build(); }
    private URI uri(String path) { return URI.create("http://localhost:"+port+path); }
    private HttpResponse<String> get(HttpClient client,String path) throws Exception { return client.send(HttpRequest.newBuilder(uri(path)).GET().build(),HttpResponse.BodyHandlers.ofString()); }
    private HttpResponse<String> post(HttpClient client,String path,Map<String,String> form,String clientId) throws Exception {
        String body=form.entrySet().stream().map(e->enc(e.getKey())+"="+enc(e.getValue())).collect(java.util.stream.Collectors.joining("&"));
        var request=HttpRequest.newBuilder(uri(path)).header("Content-Type","application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body));
        if(clientId!=null && !clientId.equals("native")) request.header("Authorization","Basic "+Base64.getEncoder().encodeToString((clientId+":"+SECRET+"-"+clientId).getBytes(StandardCharsets.UTF_8)));
        return client.send(request.build(),HttpResponse.BodyHandlers.ofString());
    }
    private String authorize(String client,String verifier) throws Exception {
        String challenge=Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        return "/oauth/authorize?response_type=code&client_id="+client+"&redirect_uri="+enc(CALLBACK)+"&scope=openid%20profile%20api.read&state=test-state-123&nonce=test-nonce-123&code_challenge_method=S256&code_challenge="+challenge;
    }
    private String code(HttpClient client,String clientId,String verifier) throws Exception {
        String path=authorize(clientId,verifier); var first=get(client,path);
        if(first.statusCode()!=302 || !first.headers().firstValue("Location").orElse("").startsWith(CALLBACK)) {
            login(client);
            first=get(client,path);
        }
        assertEquals(302,first.statusCode(),first.body()); String location=first.headers().firstValue("Location").orElseThrow();
        assertTrue(location.startsWith(CALLBACK),location);
        for(String pair:URI.create(location).getRawQuery().split("&")) if(pair.startsWith("code=")) return URLDecoder.decode(pair.substring(5),StandardCharsets.UTF_8);
        throw new AssertionError(location);
    }
    private void login(HttpClient client) throws Exception {
        var page=get(client,"/login");Matcher csrf=Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"").matcher(page.body());assertTrue(csrf.find(),page.body());
        var response=post(client,"/login",Map.of("username","E001","password",directory.password,"_csrf",csrf.group(1)),null);assertEquals(302,response.statusCode(),response.body());
    }
    private HttpResponse<String> postJson(HttpClient client,String path,Object value) throws Exception {
        var csrf=json.readTree(get(client,"/api/session/csrf").body());
        return client.send(HttpRequest.newBuilder(uri(path)).header("Content-Type","application/json").header(csrf.get("header_name").asText(),csrf.get("token").asText())
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(value))).build(),HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> recoveryJson(HttpClient client,String path,Object value,String key) throws Exception {
        var csrf=json.readTree(get(client,"/api/public/csrf").body());
        var request=HttpRequest.newBuilder(uri(path)).header("Content-Type","application/json").header(csrf.get("header_name").asText(),csrf.get("token").asText());
        if(key!=null)request.header("Idempotency-Key",key);
        return client.send(request.POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(value))).build(),HttpResponse.BodyHandlers.ofString());
    }
    private void contact(){jdbc.update("INSERT INTO recovery_contact(user_id,email,contact_version,verified_at,evidence_ref) VALUES (?,'verified@example.test',?,now(),'ticket:verified-roster')",user,UUID.randomUUID());}
    private String emailProof() throws Exception {
        assertEquals(202,recoveryJson(browser(),"/api/password/reset/request",Map.of("employee_no","E001"),null).statusCode());
        assertTrue(mailWorker.runOnce());URI link=URI.create(mail.links.get(mail.links.size()-1));assertNull(link.getRawQuery());return link.getFragment().substring("token=".length());
    }
    @Test void emailRecoveryDoesNotEnumerateAndBindsOneTimeGrantToVerifyingBrowser() throws Exception {
        contact();var old=tokens(browser(),"web");HttpClient owner=browser(),stranger=browser();
        assertEquals(403,owner.send(HttpRequest.newBuilder(uri("/api/password/reset/request")).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString("{\"employee_no\":\"E001\"}")).build(),HttpResponse.BodyHandlers.ofString()).statusCode());
        var known=recoveryJson(owner,"/api/password/reset/request",Map.of("employee_no","E001"),null);
        var unknown=recoveryJson(stranger,"/api/password/reset/request",Map.of("employee_no","missing"),null);
        assertEquals(202,known.statusCode());assertEquals(known.body(),unknown.body());assertTrue(mail.links.isEmpty());
        assertTrue(mailWorker.runOnce());assertEquals(List.of("verified@example.test"),mail.recipients);
        String proof=URI.create(mail.links.get(0)).getFragment().substring("token=".length());
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM reset_email_challenge WHERE token_digest=?",Integer.class,proof));
        assertEquals(405,get(owner,"/api/password/reset/verify").statusCode());
        var verified=recoveryJson(owner,"/api/password/reset/verify",Map.of("token",proof),null);assertEquals(200,verified.statusCode(),verified.body());
        String grant=json.readTree(verified.body()).get("reset_token").asText();
        assertEquals(400,recoveryJson(owner,"/api/password/reset/verify",Map.of("token",proof),null).statusCode());
        var body=Map.of("reset_token",grant,"new_password",NEW,"confirm_password",NEW);String key=UUID.randomUUID().toString();
        assertEquals(400,recoveryJson(stranger,"/api/password/reset/confirm",body,key).statusCode());
        var changed=recoveryJson(owner,"/api/password/reset/confirm",body,key);assertEquals(200,changed.statusCode(),changed.body());
        var replay=recoveryJson(owner,"/api/password/reset/confirm",body,key);assertEquals(200,replay.statusCode(),replay.body());assertEquals(json.readTree(changed.body()).get("id"),json.readTree(replay.body()).get("id"));
        String operation=json.readTree(changed.body()).get("id").asText();assertEquals(200,get(owner,"/api/password/reset/operations/"+operation).statusCode());
        assertEquals(404,get(stranger,"/api/password/reset/operations/"+operation).statusCode());
        assertEquals(401,api(old.get("access_token").asText()).statusCode());
        assertEquals(NEW,directory.password);
    }
    @Test void expiredEmailProofAndContactChangeCannotAuthorizeResetOrUseOldDeliveryTask() throws Exception {
        contact();String expired=emailProof();jdbc.execute("UPDATE reset_email_challenge SET expires_at=now()-interval '1 second'");
        assertEquals(400,recoveryJson(browser(),"/api/password/reset/verify",Map.of("token",expired),null).statusCode());
        String old=emailProof();recovery.request("E001","local-test");
        new RecoveryContactProvisioner(jdbc,transactions,Clock.systemUTC()).provision(user,"changed@example.test","ticket:verified-change");
        assertEquals(400,recoveryJson(browser(),"/api/password/reset/verify",Map.of("token",old),null).statusCode());
        int deliveries=mail.links.size();assertTrue(mailWorker.runOnce());assertEquals(deliveries,mail.links.size());
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM reset_mail_request WHERE state='BLOCKED'",Integer.class));
    }
    @Test void failedEmailDeliveryRetriesWithNewProofAndStaleLeaseCannotRecordSuccess() throws Exception {
        contact();mail.fail=true;String old=emailProof();
        assertEquals("PENDING",jdbc.queryForObject("SELECT state FROM reset_mail_request",String.class));
        jdbc.execute("UPDATE reset_mail_request SET next_attempt_at=now()-interval '1 second'");assertTrue(mailWorker.runOnce());
        String fresh=URI.create(mail.links.get(1)).getFragment().substring("token=".length());assertNotEquals(old,fresh);
        assertEquals(400,recoveryJson(browser(),"/api/password/reset/verify",Map.of("token",old),null).statusCode());
        mail.fail=false;mail.beforeSend=()->jdbc.update("UPDATE reset_mail_request SET lease_token=?,lease_until=now()+interval '1 minute'",UUID.randomUUID());
        jdbc.execute("UPDATE reset_mail_request SET next_attempt_at=now()-interval '1 second'");assertTrue(mailWorker.runOnce());
        assertEquals("RUNNING",jdbc.queryForObject("SELECT state FROM reset_mail_request",String.class));
        jdbc.execute("UPDATE reset_mail_request SET lease_until=now()-interval '1 second',attempts=5");assertFalse(mailWorker.runOnce());
        assertEquals("DEAD",jdbc.queryForObject("SELECT state FROM reset_mail_request",String.class));
    }
    @Test void concurrentEmailVerificationConsumesProofOnlyOnce() throws Exception {
        contact();String proof=emailProof();ExecutorService pool=Executors.newFixedThreadPool(2);
        java.util.concurrent.Callable<Boolean> verify=()->{try{recovery.verify(proof,"browser-session");return true;}catch(org.springframework.web.server.ResponseStatusException e){return false;}};
        try {var first=pool.submit(verify);var second=pool.submit(verify);assertNotEquals(first.get(10,TimeUnit.SECONDS),second.get(10,TimeUnit.SECONDS));}
        finally{pool.shutdownNow();}
        assertEquals(1,jdbc.queryForObject("SELECT count(*) FROM password_reset_grant",Integer.class));
    }
    @Test void anonymousRecoveryRateLimitReturnsSameAcceptanceWithoutExcessMailTasks() throws Exception {
        contact();HttpClient browser=browser();
        for(int attempt=0;attempt<6;attempt++){
            var response=recoveryJson(browser,"/api/password/reset/request",Map.of("employee_no","E001"),null);assertEquals(202,response.statusCode(),response.body());
        }
        assertEquals(5,jdbc.queryForObject("SELECT count(*) FROM reset_mail_request",Integer.class));assertTrue(mail.links.isEmpty());
    }
    @Test void packagedContactCliRequiresVerifiedEvidenceAndFencesExistingCredentials() throws Exception {
        Path input=Path.of("target","protocol-test","recovery-contact.json"),log=Path.of("target","protocol-test","recovery-cli.log");
        Files.writeString(input,json.writeValueAsString(Map.of("userId",user.toString(),"email","cli-verified@example.test","evidenceRef","ticket:roster-verification")));
        var command=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin",windows()?"java.exe":"java").toString(),
                "-Dloader.main=com.unipass.server.RecoveryAdminCli","-cp",Path.of("target","iam-server-0.1.0-SNAPSHOT-exec.jar").toAbsolutePath().toString(),
                "org.springframework.boot.loader.launch.PropertiesLauncher","provision-contact",input.toAbsolutePath().toString());
        command.environment().put("UNIPASS_DB_URL",postgres.getJdbcUrl("postgres","postgres"));command.environment().put("UNIPASS_DB_USER","postgres");command.environment().put("UNIPASS_DB_PASSWORD","test");
        Process process=command.redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try {
            assertTrue(process.waitFor(20,TimeUnit.SECONDS));assertEquals(0,process.exitValue(),Files.readString(log));
            assertEquals(1L,jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?",Long.class,user));
            assertEquals("cli-verified@example.test",jdbc.queryForObject("SELECT email FROM recovery_contact WHERE user_id=?",String.class,user));
            assertFalse(Files.readString(log).contains("cli-verified@example.test"));
        }finally{if(process.isAlive())process.destroyForcibly();}
    }
    private HttpClient administrator() throws Exception {
        jdbc.update("INSERT INTO iam_user_role(user_id,role) VALUES (?,'ROLE_ADMIN_PASSWORD_RESET'),(?,'ROLE_ADMIN_PASSWORD_RECOVERY')",user,user);
        byte[] secret=seedFactor();HttpClient browser=browser();login(browser);
        String context=json.readTree(postJson(browser,"/api/mfa/context",Map.of()).body()).get("context").asText();
        String challenge=json.readTree(postJson(browser,"/api/mfa/challenges",Map.of("context",context)).body()).get("challenge").asText();
        var verified=postJson(browser,"/api/mfa/verify",Map.of("context",context,"challenge",challenge,"code",otp(secret,Instant.now())));assertEquals(200,verified.statusCode(),verified.body());return browser;
    }
    private UUID target(){
        UUID target=UUID.randomUUID();jdbc.update("INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version) VALUES (?,'E002',?,'OPENLDAP','uid=two,dc=example','Target','ACTIVE','hr',1)",target,target);return target;
    }
    @Test void missingRedisGenerationDeniesOldCredentialsBeforeAndAfterRecovery() throws Exception {
        HttpClient browser=browser();var before=tokens(browser,"web");
        redisTemplate.delete(securityState.generationKey());
        assertEquals(401,api(before.get("access_token").asText()).statusCode());
        assertEquals(503,get(browser,"/api/session/me").statusCode());
        assertTrue(securityState.recoverIfNeeded());assertFalse(securityState.recoverIfNeeded());
        assertEquals(1L,jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?",Long.class,user));
        assertEquals(401,api(before.get("access_token").asText()).statusCode());
        assertEquals(400,refresh("web",before.get("refresh_token").asText()).statusCode());
        assertEquals(401,get(browser,"/api/session/me").statusCode());
        assertEquals(200,api(tokens(browser(),"web").get("access_token").asText()).statusCode());
    }
    @Test void actualRedisDataLossCannotRehabilitateJwtOrRefreshToken() throws Exception {
        var before=tokens(browser(),"web");
        redisTemplate.execute((org.springframework.data.redis.core.RedisCallback<Void>)connection->{connection.serverCommands().flushDb();return null;});
        assertEquals(401,api(before.get("access_token").asText()).statusCode());
        assertTrue(securityState.recoverIfNeeded());
        assertEquals(401,api(before.get("access_token").asText()).statusCode());
        assertEquals(400,refresh("web",before.get("refresh_token").asText()).statusCode());
    }
    @Test void redisProcessRestartIsDetectedEvenWhenGenerationMarkerIsRestored() throws Exception {
        var before=tokens(browser(),"web");String marker=redisTemplate.opsForValue().get(securityState.generationKey());String previousRun=securityState.current().runId();
        redis.destroy();assertTrue(redis.waitFor(10,TimeUnit.SECONDS));
        Path root=Path.of("target","protocol-test").toAbsolutePath();
        String executable=System.getProperty("test.redis.executable",System.getenv().getOrDefault("UNIPASS_TEST_REDIS_EXECUTABLE","redis-server"));
        redis=new ProcessBuilder(executable,"--bind","127.0.0.1","--port",Integer.toString(redisPort),"--save","","--appendonly","no","--requirepass",redisPassword,"--dir",root.toString().replace('\\','/'))
                .redirectErrorStream(true).redirectOutput(root.resolve("redis-restart.log").toFile()).start();
        Process owned=redis;Runtime.getRuntime().addShutdownHook(new Thread(()->{if(owned.isAlive())owned.destroy();}));
        boolean ready=false;
        for(int attempt=0;attempt<100;attempt++){
            if(!redis.isAlive())throw new IllegalStateException("Restarted Redis exited");
            try {redisTemplate.opsForValue().set(securityState.generationKey(),marker);ready=true;break;}
            catch(RuntimeException e){Thread.sleep(50);}
        }
        assertTrue(ready);assertNotEquals(previousRun,securityState.current().runId());
        assertEquals(401,api(before.get("access_token").asText()).statusCode());
        assertTrue(securityState.recoverIfNeeded());assertEquals(401,api(before.get("access_token").asText()).statusCode());
        assertEquals(400,refresh("web",before.get("refresh_token").asText()).statusCode());
    }
    @Test void concurrentRecoveryFencesAnIdentityExactlyOnce() throws Exception {
        tokens(browser(),"web");long baseline=jdbc.queryForObject("SELECT count(*) FROM auth_runtime_recovery",Long.class);
        redisTemplate.delete(securityState.generationKey());ExecutorService pool=Executors.newFixedThreadPool(2);
        try {var first=pool.submit(()->securityState.recoverIfNeeded());var second=pool.submit(()->securityState.recoverIfNeeded());assertNotEquals(first.get(10,TimeUnit.SECONDS),second.get(10,TimeUnit.SECONDS));}
        finally{pool.shutdownNow();}
        assertEquals(1L,jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?",Long.class,user));
        assertEquals(baseline+1,jdbc.queryForObject("SELECT count(*) FROM auth_runtime_recovery",Long.class));
    }
    @Test void redisSideEffectFollowedByPgCommitFailureStaysDeniedUntilRecovery() throws Exception {
        var before=tokens(browser(),"web");String original=jdbc.queryForObject("SELECT redis_generation::text FROM auth_runtime_state",String.class);
        jdbc.execute("CREATE FUNCTION fail_auth_runtime_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test commit failure'; END $$");
        jdbc.execute("CREATE CONSTRAINT TRIGGER fail_auth_runtime_commit AFTER UPDATE ON auth_runtime_state DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_auth_runtime_commit()");
        redisTemplate.delete(securityState.generationKey());
        try {
            assertThrows(RuntimeException.class,()->securityState.recoverIfNeeded());
            assertEquals(original,jdbc.queryForObject("SELECT redis_generation::text FROM auth_runtime_state",String.class));
            assertNotEquals(original,redisTemplate.opsForValue().get(securityState.generationKey()));
            assertEquals(0L,jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?",Long.class,user));
            assertEquals(401,api(before.get("access_token").asText()).statusCode());
        }finally{jdbc.execute("DROP TRIGGER fail_auth_runtime_commit ON auth_runtime_state");jdbc.execute("DROP FUNCTION fail_auth_runtime_commit()");}
        assertTrue(securityState.recoverIfNeeded());assertEquals(401,api(before.get("access_token").asText()).statusCode());
    }
    @Test void redisRecoveryPreservesBlockedPasswordFenceForEvidenceRecovery() throws Exception {
        var before=tokens(browser(),"web");UUID admin=target(),operation=UUID.randomUUID();
        jdbc.update("UPDATE iam_user SET password_gate='BLOCKED',auth_epoch=1 WHERE id=?",user);
        jdbc.update("INSERT INTO password_operation(id,user_id,idempotency_key,state,operation_type,fenced_epoch,lease_until,created_at) VALUES (?,?,'test-blocked-fence','UNKNOWN','CHANGE',1,now()-interval '1 minute',now())",operation,user);
        redisTemplate.delete(securityState.generationKey());assertTrue(securityState.recoverIfNeeded());
        assertEquals(1L,jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?",Long.class,user));
        var actor=new com.unipass.password.AuthenticatedActor(admin,1,Instant.now(),Set.of("PASSWORD_RECOVERY"),Instant.now());
        assertEquals(com.unipass.password.PasswordOperation.State.REJECTED,passwords.recover(actor,operation,false,"ticket:redis-incident/evidence").state());
        assertEquals("OPEN",jdbc.queryForObject("SELECT password_gate FROM iam_user WHERE id=?",String.class,user));
        assertEquals(401,api(before.get("access_token").asText()).statusCode());
    }
    @Test void administrativeResetRequiresFreshMfaAndLiveRoleAndPersistsReason() throws Exception {
        HttpClient weak=browser();login(weak);UUID target=target();
        var body=Map.of("reason","Helpdesk identity verified","new_password",NEW,"confirm_password",NEW);String key=UUID.randomUUID().toString();
        assertEquals(403,recoveryJson(weak,"/api/admin/password/users/"+target+"/reset",body,key).statusCode());
        HttpClient admin=administrator();var response=recoveryJson(admin,"/api/admin/password/users/"+target+"/reset",body,key);assertEquals(200,response.statusCode(),response.body());
        assertTrue(jdbc.queryForObject("SELECT must_change_password FROM iam_user WHERE id=?",Boolean.class,target));
        assertEquals("Helpdesk identity verified",jdbc.queryForObject("SELECT reason FROM admin_password_action",String.class));
        String operation=json.readTree(response.body()).get("id").asText();assertEquals(200,get(admin,"/api/admin/password/operations/"+operation).statusCode());
        jdbc.update("DELETE FROM iam_user_role WHERE user_id=? AND role='ROLE_ADMIN_PASSWORD_RESET'",user);
        assertEquals(403,recoveryJson(admin,"/api/admin/password/users/"+target+"/reset",body,key).statusCode());
    }
    @Test void administrativeRecoveryRequiresEvidenceExpiredLeaseAndIdempotentDecision() throws Exception {
        UUID target=target(),operation=UUID.randomUUID();HttpClient admin=administrator();
        jdbc.update("UPDATE iam_user SET password_gate='BLOCKED',auth_epoch=1 WHERE id=?",target);
        jdbc.update("INSERT INTO password_operation(id,user_id,idempotency_key,state,operation_type,fenced_epoch,lease_until,created_at) VALUES (?,?,'test-unknown-operation','UNKNOWN','CHANGE',1,now()+interval '1 minute',now())",operation,target);
        String path="/api/admin/password/operations/"+operation+"/recover",key=UUID.randomUUID().toString();
        var body=Map.of("confirmed_committed",false,"reason","Directory evidence reviewed","evidence_ref","ticket:SEC-200/evidence");
        assertEquals(403,recoveryJson(admin,path,body,key).statusCode());
        jdbc.update("UPDATE password_operation SET lease_until=now()-interval '1 second' WHERE id=?",operation);
        var response=recoveryJson(admin,path,body,key);assertEquals(200,response.statusCode(),response.body());assertEquals("REJECTED",json.readTree(response.body()).get("state").asText());
        assertEquals(200,recoveryJson(admin,path,body,key).statusCode());
        assertEquals("OPEN",jdbc.queryForObject("SELECT password_gate FROM iam_user WHERE id=?",String.class,target));
        assertEquals(403,recoveryJson(admin,path,Map.of("confirmed_committed",true,"reason","Contradictory decision","evidence_ref","ticket:SEC-200/evidence"),UUID.randomUUID().toString()).statusCode());
    }
    private String otp(byte[] secret,Instant instant) throws Exception {
        return new com.eatthepath.otp.TimeBasedOneTimePasswordGenerator().generateOneTimePasswordString(new javax.crypto.spec.SecretKeySpec(secret,"HmacSHA1"),instant,Locale.ROOT);
    }
    private byte[] seedFactor() {
        byte[] secret=new byte[20];new java.security.SecureRandom().nextBytes(secret);
        var cipher=new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]));
        jdbc.update("INSERT INTO mfa_totp(user_id,secret_cipher,enabled) VALUES (?,?,true)",user,cipher.encrypt(user,secret));return secret;
    }
    private IdentityPrincipal principal(){return new IdentityPrincipal(user,0,Instant.now(),List.of("ROLE_USER"));}
    @Test void totpEnrollmentFencesOldTokensAndAuthorizationRequiresBoundMfaChallenge() throws Exception {
        HttpClient browser=browser();var previous=tokens(browser,"web");
        assertEquals(403,browser.send(HttpRequest.newBuilder(uri("/api/mfa/enrollment")).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString("{}")).build(),HttpResponse.BodyHandlers.ofString()).statusCode());
        var enrollment=postJson(browser,"/api/mfa/enrollment",Map.of());assertEquals(200,enrollment.statusCode(),enrollment.body());
        var details=json.readTree(enrollment.body());byte[] raw=new org.apache.commons.codec.binary.Base32().decode(details.get("secret").asText());
        assertFalse(Arrays.equals(raw,jdbc.queryForObject("SELECT secret_cipher FROM mfa_totp WHERE user_id=?",byte[].class,user)));
        var confirmed=postJson(browser,"/api/mfa/enrollment/confirm",Map.of("code",otp(raw,Instant.now().minusSeconds(30))));assertEquals(200,confirmed.statusCode(),confirmed.body());
        assertEquals(401,api(previous.get("access_token").asText()).statusCode());
        assertEquals(401,get(browser,"/api/session/me").statusCode());login(browser);
        var required=get(browser,authorize("web","v".repeat(64)));assertEquals(401,required.statusCode(),required.body());
        String context=json.readTree(required.body()).get("context").asText();
        var challenge=postJson(browser,"/api/mfa/challenges",Map.of("context",context));assertEquals(200,challenge.statusCode(),challenge.body());
        String challengeId=json.readTree(challenge.body()).get("challenge").asText();
        assertEquals(400,postJson(browser,"/api/mfa/verify",Map.of("context",UUID.randomUUID().toString(),"challenge",challengeId,"code",otp(raw,Instant.now()))).statusCode());
        var verified=postJson(browser,"/api/mfa/verify",Map.of("context",context,"challenge",challengeId,"code",otp(raw,Instant.now())));assertEquals(200,verified.statusCode(),verified.body());
        assertEquals(400,postJson(browser,"/api/mfa/verify",Map.of("context",context,"challenge",challengeId,"code",otp(raw,Instant.now()))).statusCode());
        var strong=tokens(browser,"web");JsonNode claims=json.readTree(Base64.getUrlDecoder().decode(strong.get("id_token").asText().split("\\.")[1]));
        assertEquals(List.of("pwd","otp"),json.convertValue(claims.get("amr"),List.class));
        assertEquals(200,refresh("web",strong.get("refresh_token").asText()).statusCode());
    }
    @Test void mfaChallengeCannotMoveBetweenSessionsOrContextsAndExpires() throws Exception {
        byte[] secret=seedFactor();var principal=principal();UUID context=UUID.randomUUID(),challenge=mfa.challenge(principal,"first-session",context);
        assertThrows(org.springframework.web.server.ResponseStatusException.class,()->mfa.verifyChallenge(principal,"another-session",context,challenge,otp(secret,Instant.now())));
        assertThrows(org.springframework.web.server.ResponseStatusException.class,()->mfa.verifyChallenge(principal,"first-session",UUID.randomUUID(),challenge,otp(secret,Instant.now())));
        jdbc.update("UPDATE mfa_challenge SET expires_at=now()-interval '1 minute' WHERE id=?",challenge);
        assertThrows(org.springframework.web.server.ResponseStatusException.class,()->mfa.verifyChallenge(principal,"first-session",context,challenge,otp(secret,Instant.now())));
        UUID fresh=mfa.challenge(principal,"first-session",context);
        String acceptedCode=otp(secret,Instant.now());assertNotNull(mfa.verifyChallenge(principal,"first-session",context,fresh,acceptedCode));
        UUID reuse=mfa.challenge(principal,"first-session",context);
        assertThrows(org.springframework.web.server.ResponseStatusException.class,()->mfa.verifyChallenge(principal,"first-session",context,reuse,acceptedCode));
    }
    @Test void mfaFailureLockPersistsAcrossNewChallengesAndCommitsOnRejection() throws Exception {
        byte[] secret=seedFactor();var principal=principal();UUID context=UUID.randomUUID();
        for(int attempt=0;attempt<5;attempt++){
            UUID challenge=mfa.challenge(principal,"session",context);
            assertThrows(org.springframework.web.server.ResponseStatusException.class,()->mfa.verifyChallenge(principal,"session",context,challenge,"invalid"));
        }
        assertEquals(5,jdbc.queryForObject("SELECT failed_attempts FROM mfa_totp WHERE user_id=?",Integer.class,user));
        UUID challenge=mfa.challenge(principal,"session",context);
        assertThrows(org.springframework.web.server.ResponseStatusException.class,()->mfa.verifyChallenge(principal,"session",context,challenge,otp(secret,Instant.now())));
        jdbc.update("UPDATE mfa_totp SET locked_until=now()-interval '1 minute' WHERE user_id=?",user);
        assertNotNull(mfa.verifyChallenge(principal,"session",context,challenge,otp(secret,Instant.now())));
        assertEquals(0,jdbc.queryForObject("SELECT failed_attempts FROM mfa_totp WHERE user_id=?",Integer.class,user));
    }
    @Test void concurrentMfaVerificationConsumesTheStepAndChallengeExactlyOnce() throws Exception {
        byte[] secret=seedFactor();var principal=principal();UUID context=UUID.randomUUID(),challenge=mfa.challenge(principal,"session",context);String code=otp(secret,Instant.now());
        ExecutorService pool=Executors.newFixedThreadPool(2);
        java.util.concurrent.Callable<Boolean> action=()->{try{mfa.verifyChallenge(principal,"session",context,challenge,code);return true;}catch(org.springframework.web.server.ResponseStatusException e){return false;}};
        try {var first=pool.submit(action);var second=pool.submit(action);assertNotEquals(first.get(10,TimeUnit.SECONDS),second.get(10,TimeUnit.SECONDS));}
        finally {pool.shutdownNow();}
    }
    private JsonNode tokens(HttpClient browser,String clientId) throws Exception {
        String verifier="v".repeat(64), code=code(browser,clientId,verifier);
        var response=exchange(clientId,code,verifier); assertEquals(200,response.statusCode(),response.body()); return json.readTree(response.body());
    }
    private HttpResponse<String> exchange(String clientId,String code,String verifier) throws Exception {
        return post(browser(),"/oauth/token",Map.of("grant_type","authorization_code","code",code,"redirect_uri",CALLBACK,"code_verifier",verifier,"client_id",clientId),clientId);
    }
    private HttpResponse<String> refresh(String clientId,String token) throws Exception {
        return post(browser(),"/oauth/token",Map.of("grant_type","refresh_token","refresh_token",token,"client_id",clientId),clientId);
    }
    private HttpResponse<String> api(String token) throws Exception {
        return browser().send(HttpRequest.newBuilder(uri("/api/resource/me")).header("Authorization","Bearer "+token).GET().build(),HttpResponse.BodyHandlers.ofString());
    }
    @Test void discoveryAndJwksArePublicAndPrivateKeyNeverLeavesServer() throws Exception {
        var discovery=get(browser(),"/.well-known/openid-configuration"); assertEquals(200,discovery.statusCode(),discovery.body());
        assertEquals(ISSUER,json.readTree(discovery.body()).get("issuer").asText());
        var keys=get(browser(),"/oauth/jwks"); assertEquals(200,keys.statusCode()); assertFalse(json.readTree(keys.body()).get("keys").get(0).has("d"));
    }
    @Test void strictRedirectPkceAndStateAreCheckedBeforeLoginRedirect() throws Exception {
        String path=authorize("web","v".repeat(64));
        assertEquals(400,get(browser(),path.replace("code_challenge_method=S256","code_challenge_method=plain")).statusCode());
        assertEquals(400,get(browser(),path.replace(enc(CALLBACK),enc(CALLBACK+"/evil"))).statusCode());
        assertEquals(400,get(browser(),path.replace("state=test-state-123","state=")).statusCode());
    }
    @Test void authorizationCodeIssuesSignedJwtAndStoresOnlyDigests() throws Exception {
        var tokens=tokens(browser(),"web"); String access=tokens.get("access_token").asText(), refresh=tokens.get("refresh_token").asText();
        assertEquals(200,api(access).statusCode());
        assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM oauth2_authorization WHERE access_token_value=? OR refresh_token_value=?",Integer.class,access,refresh));
        assertTrue(jdbc.queryForObject("SELECT refresh_token_value FROM oauth2_authorization",String.class).startsWith("sha256:"));
        assertNotNull(authorizations.findByToken(refresh,org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN));
        var userinfo=browser().send(HttpRequest.newBuilder(uri("/oauth/userinfo")).header("Authorization","Bearer "+access).GET().build(),HttpResponse.BodyHandlers.ofString());
        assertEquals(200,userinfo.statusCode(),userinfo.body()); assertEquals(user.toString(),json.readTree(userinfo.body()).get("sub").asText());
    }
    @Test void refreshRotationDetectsReuseAndRevokesTheFamily() throws Exception {
        var first=tokens(browser(),"web"); var rotated=refresh("web",first.get("refresh_token").asText()); assertEquals(200,rotated.statusCode(),rotated.body());
        var next=json.readTree(rotated.body()); assertNotEquals(first.get("refresh_token"),next.get("refresh_token"));
        assertEquals(400,refresh("web",first.get("refresh_token").asText()).statusCode());
        assertEquals(401,api(next.get("access_token").asText()).statusCode());
        assertEquals(400,refresh("web",next.get("refresh_token").asText()).statusCode());
    }
    @Test void nativePublicClientReceivesAndRotatesRefreshWithoutSecret() throws Exception {
        var first=tokens(browser(),"native"); assertTrue(first.has("refresh_token"));
        var next=refresh("native",first.get("refresh_token").asText()); assertEquals(200,next.statusCode(),next.body());
        assertNotEquals(first.get("refresh_token"),json.readTree(next.body()).get("refresh_token"));
    }
    @Test void accessTokenCannotBeUsedAsRefreshToken() throws Exception {
        var first=tokens(browser(),"web"); assertEquals(400,refresh("web",first.get("access_token").asText()).statusCode());
        assertEquals(200,api(first.get("access_token").asText()).statusCode());
    }
    @Test void codeIsConsumedExactlyOnceUnderConcurrentExchange() throws Exception {
        String verifier="v".repeat(64), code=code(browser(),"web",verifier); ExecutorService pool=Executors.newFixedThreadPool(2);
        try { var a=pool.submit(()->exchange("web",code,verifier)); var b=pool.submit(()->exchange("web",code,verifier));
            List<Integer> statuses=List.of(a.get(15,TimeUnit.SECONDS).statusCode(),b.get(15,TimeUnit.SECONDS).statusCode()); assertEquals(1,statuses.stream().filter(s->s==200).count(),statuses.toString());
        } finally { pool.shutdownNow(); }
    }
    @Test void wrongPkceVerifierAndWrongClientCannotRedeemCredentials() throws Exception {
        String verifier="v".repeat(64), code=code(browser(),"web",verifier);
        assertEquals(400,exchange("web",code,"w".repeat(64)).statusCode());
        var first=tokens(browser(),"web");
        assertEquals(400,refresh("web-two",first.get("refresh_token").asText()).statusCode());
        assertEquals(200,refresh("web",first.get("refresh_token").asText()).statusCode());
        assertEquals(401,api(first.get("id_token").asText()).statusCode());
    }
    @Test void revocationMakesJwtAndRefreshUnusable() throws Exception {
        var first=tokens(browser(),"web");
        var revoked=post(browser(),"/oauth/revoke",Map.of("token",first.get("refresh_token").asText(),"token_type_hint","refresh_token"),"web");
        assertEquals(200,revoked.statusCode(),revoked.body());
        assertEquals(401,api(first.get("access_token").asText()).statusCode());
        assertEquals(400,refresh("web",first.get("refresh_token").asText()).statusCode());
    }
    @Test void oidcLogoutValidatesCallbackAndGloballyFencesTokensAndSessions() throws Exception {
        HttpClient browser=browser(); var first=tokens(browser,"web");
        String idToken=first.get("id_token").asText();
        JsonNode claims=json.readTree(Base64.getUrlDecoder().decode(idToken.split("\\.")[1]));
        assertTrue(claims.has("sid")); assertNotEquals(claims.get("sid"),claims.get("unipass_family"));
        var second=tokens(browser,"web-two");
        String logout="/oauth/logout?id_token_hint="+enc(idToken)+"&post_logout_redirect_uri=";
        var invalid=get(browser,logout+enc("https://evil.example/")); assertEquals(400,invalid.statusCode(),invalid.body());
        assertEquals(200,api(first.get("access_token").asText()).statusCode());
        var response=get(browser,logout+enc("https://rp.example.test/")+"&state=logout-state");
        assertEquals(302,response.statusCode(),response.body());
        assertEquals("https://rp.example.test/?state=logout-state",response.headers().firstValue("Location").orElseThrow());
        assertEquals(401,api(first.get("access_token").asText()).statusCode());
        assertEquals(401,api(second.get("access_token").asText()).statusCode());
        assertEquals(400,refresh("web",first.get("refresh_token").asText()).statusCode());
    }
    @Test void expiredPasswordAllowsSelfServiceButPreventsAuthorizationAndTokenExchange() throws Exception {
        HttpClient browser=browser(); String verifier="v".repeat(64), code=code(browser,"web",verifier);
        jdbc.update("UPDATE iam_user SET must_change_password=true WHERE id=?",user);
        assertEquals(403,get(browser,authorize("web",verifier)).statusCode());
        assertEquals(200,get(browser,"/api/session/csrf").statusCode());
        assertEquals(400,exchange("web",code,verifier).statusCode());
    }
    @Test void missingAccountStateFailsClosedForApiAndBrowser() throws Exception {
        HttpClient browser=browser(); var first=tokens(browser,"web");
        jdbc.execute("ALTER TABLE iam_user RENAME TO iam_user_fault_test");
        try {
            assertEquals(401,api(first.get("access_token").asText()).statusCode());
            var response=get(browser,"/api/session/me"); assertEquals(503,response.statusCode());
            assertFalse(response.body().contains("SELECT"));
        } finally { jdbc.execute("ALTER TABLE iam_user_fault_test RENAME TO iam_user"); }
    }
    @Test void packagedOperatorCliRegistersClientWithoutStartingWebServer() throws Exception {
        Path input=Path.of("target","protocol-test","client.json");
        Files.writeString(input,"{\"client_id\":\"cli-client\",\"name\":\"CLI test\",\"kind\":\"CONFIDENTIAL\",\"redirect_uris\":[\"https://cli.example/cb\"],\"post_logout_redirect_uris\":[],\"scopes\":[\"openid\"]}");
        Path log=Path.of("target","protocol-test","client-cli.log");
        var command=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin",windows()?"java.exe":"java").toString(),
                "-Dloader.main=com.unipass.server.ClientAdminCli","-cp",Path.of("target","iam-server-0.1.0-SNAPSHOT-exec.jar").toAbsolutePath().toString(),
                "org.springframework.boot.loader.launch.PropertiesLauncher","register",input.toAbsolutePath().toString());
        command.environment().put("UNIPASS_DB_URL",postgres.getJdbcUrl("postgres","postgres"));
        command.environment().put("UNIPASS_DB_USER","postgres");command.environment().put("UNIPASS_DB_PASSWORD","test");
        command.environment().put("UNIPASS_CLIENT_SECRET","test-only-generated-client-secret-0123456789");
        Process process=command.redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try {
            assertTrue(process.waitFor(20,TimeUnit.SECONDS)); assertEquals(0,process.exitValue(),Files.readString(log));
            assertNotNull(clients.findByClientId("cli-client"));
            assertFalse(Files.readString(log).contains("test-only-generated-client-secret"));
        } finally { if(process.isAlive())process.destroyForcibly(); }
    }
    @Test void passwordChangeRequiresCsrfAndRejectsOldJwtAndSession() throws Exception {
        HttpClient browser=browser(); var token=tokens(browser,"web"); JsonNode csrf=json.readTree(get(browser,"/api/session/csrf").body());
        String body="{\"old_password\":\""+OLD+"\",\"new_password\":\""+NEW+"\",\"confirm_password\":\""+NEW+"\"}";
        var request=HttpRequest.newBuilder(uri("/api/password/change")).header("Content-Type","application/json").header("Idempotency-Key",UUID.randomUUID().toString());
        assertEquals(403,browser.send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString()).statusCode());
        var changed=browser.send(request.header(csrf.get("header_name").asText(),csrf.get("token").asText()).POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
        assertEquals(200,changed.statusCode(),changed.body()); var op=json.readTree(changed.body());
        assertEquals(200,get(browser,"/api/password/operations/"+op.get("id").asText()).statusCode());
        assertEquals(401,api(token.get("access_token").asText()).statusCode()); assertEquals(401,get(browser,"/api/session/me").statusCode());
        assertEquals(200,api(tokens(browser(),"web").get("access_token").asText()).statusCode());
    }
    static boolean windows(){return System.getProperty("os.name").startsWith("Windows");}
    static String enc(String value){return URLEncoder.encode(value,StandardCharsets.UTF_8);}
    @TestConfiguration static class TestDirectory {
        @Bean FakeDirectory fakeDirectory(){return new FakeDirectory();}
        @Bean @org.springframework.context.annotation.Primary TestMail testMail(){return new TestMail();}
    }
    static class TestMail implements RecoveryEmailSender {
        final List<String> links=new ArrayList<>(),recipients=new ArrayList<>();boolean fail;Runnable beforeSend=()->{};
        void reset(){links.clear();recipients.clear();fail=false;beforeSend=()->{};}
        public boolean available(){return true;}
        public void send(String recipient,String link){links.add(link);recipients.add(recipient);beforeSend.run();if(fail)throw new IllegalStateException("Test transport failure");}
    }
    static class FakeDirectory implements DirectoryGateway {
        volatile String password;
        @Override public DirectoryConfig.Type type(){return DirectoryConfig.Type.OPENLDAP;}
        @Override public Optional<DirectoryUser> findByStableId(String id){return Optional.of(new DirectoryUser(id,"E001","uid=one,dc=example",false));}
        @Override public boolean verifyCredential(String id,char[] value){return password.equals(new String(value));}
        @Override public void changePassword(String id,char[] old,char[] next){if(!verifyCredential(id,old))throw new DirectoryFailure(DirectoryFailure.Kind.REJECTED);password=new String(next);}
        @Override public void disableUser(String id){}
        @Override public boolean supportsPasswordReset(){return true;}
        @Override public void resetPassword(String id,char[] next){password=new String(next);}
    }
}
