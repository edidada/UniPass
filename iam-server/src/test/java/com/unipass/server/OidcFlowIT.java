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
    }
    @BeforeEach void seed() {
        jdbc.execute("TRUNCATE oauth2_authorization CASCADE"); jdbc.execute("TRUNCATE import_source CASCADE");
        user=UUID.randomUUID(); directory.password=OLD;
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
            var page=get(client,"/login"); Matcher csrf=Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"").matcher(page.body()); assertTrue(csrf.find(),page.body());
            var login=post(client,"/login",Map.of("username","E001","password",directory.password,"_csrf",csrf.group(1)),null); assertEquals(302,login.statusCode(),login.body());
            first=get(client,path);
        }
        assertEquals(302,first.statusCode(),first.body()); String location=first.headers().firstValue("Location").orElseThrow();
        assertTrue(location.startsWith(CALLBACK),location);
        for(String pair:URI.create(location).getRawQuery().split("&")) if(pair.startsWith("code=")) return URLDecoder.decode(pair.substring(5),StandardCharsets.UTF_8);
        throw new AssertionError(location);
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
    @TestConfiguration static class TestDirectory { @Bean FakeDirectory fakeDirectory(){return new FakeDirectory();} }
    static class FakeDirectory implements DirectoryGateway {
        volatile String password;
        @Override public DirectoryConfig.Type type(){return DirectoryConfig.Type.OPENLDAP;}
        @Override public Optional<DirectoryUser> findByStableId(String id){return Optional.of(new DirectoryUser(id,"E001","uid=one,dc=example",false));}
        @Override public boolean verifyCredential(String id,char[] value){return password.equals(new String(value));}
        @Override public void changePassword(String id,char[] old,char[] next){if(!verifyCredential(id,old))throw new DirectoryFailure(DirectoryFailure.Kind.REJECTED);password=new String(next);}
        @Override public void disableUser(String id){}
    }
}
