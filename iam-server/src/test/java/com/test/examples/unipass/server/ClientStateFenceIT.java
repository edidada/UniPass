package com.test.examples.unipass.server;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Authentication-time client state fence: a disabled or just-rotated client must not authenticate,
 * and the check is serialized with disable/rotate on the live registered-client row lock. Exercises
 * the fenced provider directly against an embedded PostgreSQL (no in-memory stand-in for the lock
 * semantics).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClientStateFenceIT {
  private static final UUID OPERATOR = new UUID(0, 1);
  private EmbeddedPostgres pg;
  private HikariDataSource pool;
  private JdbcTemplate jdbc;
  private TransactionTemplate tx;
  private TransactionTemplate fencedTx;
  private TransactionTemplate lockTx;
  private RegisteredClientRepository clients;
  private ClientAdminService service;
  private FencedClientSecretAuthenticationProvider fenced;
  private FencedClientSecretAuthenticationProvider fencedPkce;
  private AccountState accounts;
  private final AtomicReference<Instant> now =
      new AtomicReference<>(Instant.parse("2026-10-24T00:00:00Z"));
  private final Duration overlap = Duration.ofHours(1);
  private static final String CALLBACK = "https://app.example/callback";

  @BeforeAll
  void start() throws Exception {
    System.setProperty(
        "ot.epg.working-dir",
        Files.createDirectories(Path.of("target", "client-fence", "postgres"))
            .toAbsolutePath()
            .toString());
    pg =
        EmbeddedPostgres.builder()
            .setPort(0)
            .setServerConfig("listen_addresses", "127.0.0.1")
            .start();
    pool =
        new HikariDataSource(
            new HikariConfig() {
              {
                setDataSource(pg.getPostgresDatabase());
                setMaximumPoolSize(8);
                setConnectionTimeout(30_000);
              }
            });
    jdbc = new JdbcTemplate(pool);
    tx = new TransactionTemplate(new DataSourceTransactionManager(pool));
    fencedTx = new TransactionTemplate(new DataSourceTransactionManager(pool));
    fencedTx.setTimeout(30);
    lockTx = new TransactionTemplate(new DataSourceTransactionManager(pool));
    lockTx.setTimeout(30);
    Clock clock =
        new Clock() {
          @Override
          public ZoneId getZone() {
            return ZoneId.of("UTC");
          }

          @Override
          public Clock withZone(ZoneId zone) {
            return this;
          }

          @Override
          public Instant instant() {
            return now.get();
          }
        };
    clients = new JdbcRegisteredClientRepository(jdbc);
    Environment env = Mockito.mock(Environment.class);
    Mockito.when(
            env.getProperty(
                "unipass.clients.secret-rotation-window",
                Duration.class,
                ClientAdminService.DEFAULT_OVERLAP))
        .thenReturn(overlap);
    accounts = Mockito.mock(AccountState.class);
    Mockito.when(accounts.roles(OPERATOR)).thenReturn(List.of("ROLE_SYSTEM_ADMIN"));
    MfaService mfa = Mockito.mock(MfaService.class);
    Mockito.when(mfa.recent(Mockito.any())).thenReturn(true);
    var registration = new ClientRegistrationService(clients, false);
    service =
        new ClientAdminService(
            clients,
            jdbc,
            tx,
            accounts,
            new AdminAuditService(jdbc, clock),
            mfa,
            registration,
            clock,
            env);
    fenced =
        new FencedClientSecretAuthenticationProvider(
            clients,
            jdbc,
            fencedTx,
            new DigestAuthorizationService(jdbc, clients, accounts, tx),
            clock);
  }

  @BeforeEach
  void seed() {
    now.set(Instant.parse("2026-10-24T00:00:00Z"));
    Flyway.configure().dataSource(pool).cleanDisabled(false).load().clean();
    Flyway.configure().dataSource(pool).load().migrate();
    jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('fence-test','1')");
    jdbc.update(
        """
                INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch)
                VALUES (?,?,?,'OPENLDAP','uid='||?::text,'Op','ACTIVE','fence-test',1,5)
                """,
        OPERATOR,
        "op",
        UUID.randomUUID(),
        "op");
  }

  private IdentityPrincipal operator() {
    return new IdentityPrincipal(
        OPERATOR,
        5,
        now.get(),
        List.of("ROLE_SYSTEM_ADMIN"),
        now.get(),
        IdentityPrincipal.Method.PASSWORD,
        now.get(),
        UUID.randomUUID());
  }

  private ClientAdminService.Registration registration(String id) {
    return new ClientAdminService.Registration(
        id,
        "Test application",
        "CONFIDENTIAL",
        List.of(CALLBACK),
        List.of("https://app.example/"),
        Set.of("openid", "api.read"),
        null,
        "开通应用");
  }

  private OAuth2ClientAuthenticationToken presented(String clientId, String secret) {
    return new OAuth2ClientAuthenticationToken(
        clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, secret, Map.of());
  }

  private OAuth2ClientAuthenticationToken presented(
      String clientId, String secret, Map<String, Object> params) {
    // Registered confidential clients only support client_secret_basic (see
    // ClientRegistrationService.builder); present the additional parameters
    // under that method rather than CLIENT_SECRET_POST so the provider's method
    // check passes and the PKCE verifier is actually exercised.
    return new OAuth2ClientAuthenticationToken(
        clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, secret, params);
  }

  @Test
  void disabledClientWithValidSecretIsRejectedButEnabledSucceeds() {
    String secret = service.register(operator(), registration("crm")).secret();
    assertNotNull(fenced.authenticate(presented("crm", secret)), "enabled client authenticates");
    service.setEnabled(operator(), "crm", false, "疑似泄露", "disable-fence-0001");
    OAuth2AuthenticationException rejected =
        assertThrows(
            OAuth2AuthenticationException.class,
            () -> fenced.authenticate(presented("crm", secret)));
    assertEquals(
        OAuth2ErrorCodes.INVALID_CLIENT,
        rejected.getError().getErrorCode(),
        "disabled client must fail closed");
    // Re-enabling restores authentication.
    service.setEnabled(operator(), "crm", true, "误报解除", "enable-fence-0001");
    assertNotNull(
        fenced.authenticate(presented("crm", secret)), "re-enabled client authenticates again");
  }

  @Test
  void previousSecretWorksInsideWindowAndFailsAfterItCloses() {
    String first = service.register(operator(), registration("crm")).secret();
    String current = service.rotate(operator(), "crm", "季度轮换", "rotate-fence-0001").secret();
    assertNotNull(fenced.authenticate(presented("crm", current)), "current secret authenticates");
    assertNotNull(
        fenced.authenticate(presented("crm", first)),
        "previous secret authenticates inside window");
    now.updateAndGet(v -> v.plus(overlap).plusSeconds(1));
    assertNotNull(
        fenced.authenticate(presented("crm", current)),
        "current secret still authenticates after window");
    OAuth2AuthenticationException rejected =
        assertThrows(
            OAuth2AuthenticationException.class,
            () -> fenced.authenticate(presented("crm", first)));
    assertEquals(
        OAuth2ErrorCodes.INVALID_CLIENT,
        rejected.getError().getErrorCode(),
        "expired previous secret must fail");
  }

  @Test
  void unknownClientFallsThroughToDefaultProvider() {
    // No row -> provider returns null so the framework yields invalid_client.
    assertNull(fenced.authenticate(presented("ghost", "whatever")));
  }

  @Test
  void disableCommitsWhileAuthenticationIsPendingBlocksUntilThenFails() throws Exception {
    String secret = service.register(operator(), registration("crm")).secret();
    CountDownLatch aLocked = new CountDownLatch(1);
    CountDownLatch aCommit = new CountDownLatch(1);
    CountDownLatch bDone = new CountDownLatch(1);
    AtomicReference<OAuth2AuthenticationException> bError = new AtomicReference<>();
    AtomicReference<Throwable> aError = new AtomicReference<>();
    Thread a =
        new Thread(
            () -> {
              try {
                lockTx.execute(
                    status -> {
                      jdbc.queryForList(
                          "SELECT id FROM oauth2_registered_client WHERE client_id=? FOR UPDATE",
                          String.class,
                          "crm");
                      jdbc.update(
                          """
                    INSERT INTO oauth_client_status(client_id,disabled,reason,updated_at) VALUES (?,true,?,?)
                    ON CONFLICT (client_id) DO UPDATE SET disabled=true,reason=excluded.reason,updated_at=excluded.updated_at
                    """,
                          "crm",
                          "并发停用",
                          java.sql.Timestamp.from(now.get()));
                      aLocked.countDown();
                      try {
                        aCommit.await(20, TimeUnit.SECONDS);
                      } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                      }
                      return null;
                    });
              } catch (Throwable t) {
                aError.set(t);
              } finally {
                aLocked.countDown();
              }
            });
    a.start();
    assertTrue(aLocked.await(20, TimeUnit.SECONDS), "disabler acquired the row lock");
    Thread b =
        new Thread(
            () -> {
              try {
                fenced.authenticate(presented("crm", secret));
              } catch (OAuth2AuthenticationException e) {
                bError.set(e);
              } finally {
                bDone.countDown();
              }
            });
    b.start();
    // Let B reach the blocked FOR UPDATE before releasing the lock.
    Thread.sleep(300);
    aCommit.countDown();
    assertTrue(bDone.await(20, TimeUnit.SECONDS), "authentication finished");
    assertNotNull(bError.get(), "authentication must not succeed while/after disabled");
    assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, bError.get().getError().getErrorCode());
    a.join(20_000);
    b.join(20_000);
    assertNull(aError.get(), "disabler thread must not fail");
  }

  @Test
  void pkceIsEnforcedForAuthorizationCodeGrant() throws Exception {
    String secret = service.register(operator(), registration("crm")).secret();
    RegisteredClient client = clients.findByClientId("crm");
    assertTrue(
        client.getClientSettings().isRequireProofKey(),
        "confidential clients require PKCE by default");
    String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    byte[] digest =
        MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
    String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    String code = "authz-code-fence-1";
    OAuth2AuthorizationRequest request =
        OAuth2AuthorizationRequest.authorizationCode()
            .clientId("crm")
            .authorizationUri("/oauth/authorize")
            .redirectUri(CALLBACK)
            .scopes(Set.of("openid"))
            .additionalParameters(
                Map.of(
                    PkceParameterNames.CODE_CHALLENGE,
                    challenge,
                    PkceParameterNames.CODE_CHALLENGE_METHOD,
                    "S256"))
            .state("state")
            .build();
    OAuth2Authorization authorization =
        OAuth2Authorization.withRegisteredClient(client)
            .id("fam-fence-1")
            .principalName(OPERATOR.toString())
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .attribute(OAuth2AuthorizationRequest.class.getName(), request)
            .build();
    OAuth2AuthorizationService mockAuthz = Mockito.mock(OAuth2AuthorizationService.class);
    Mockito.when(mockAuthz.findByToken(eq(code), any())).thenReturn(authorization);
    fencedPkce =
        new FencedClientSecretAuthenticationProvider(
            clients,
            jdbc,
            fencedTx,
            mockAuthz,
            new Clock() {
              @Override
              public ZoneId getZone() {
                return ZoneId.of("UTC");
              }

              @Override
              public Clock withZone(ZoneId zone) {
                return this;
              }

              @Override
              public Instant instant() {
                return now.get();
              }
            });

    Map<String, Object> ok = new HashMap<>();
    ok.put(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
    ok.put(OAuth2ParameterNames.CODE, code);
    ok.put(PkceParameterNames.CODE_VERIFIER, verifier);
    assertNotNull(
        fencedPkce.authenticate(presented("crm", secret, ok)), "correct verifier authenticates");

    Map<String, Object> wrong = new HashMap<>(ok);
    wrong.put(PkceParameterNames.CODE_VERIFIER, "wrong-verifier");
    OAuth2AuthenticationException wrongErr =
        assertThrows(
            OAuth2AuthenticationException.class,
            () -> fencedPkce.authenticate(presented("crm", secret, wrong)));
    assertEquals(
        OAuth2ErrorCodes.INVALID_GRANT,
        wrongErr.getError().getErrorCode(),
        "wrong verifier rejected");

    Map<String, Object> missing = new HashMap<>();
    missing.put(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
    missing.put(OAuth2ParameterNames.CODE, code);
    OAuth2AuthenticationException missErr =
        assertThrows(
            OAuth2AuthenticationException.class,
            () -> fencedPkce.authenticate(presented("crm", secret, missing)));
    assertEquals(
        OAuth2ErrorCodes.INVALID_GRANT,
        missErr.getError().getErrorCode(),
        "missing verifier rejected under requireProofKey");

    // PKCE must not gate non-authorization_code grants.
    Map<String, Object> cc = new HashMap<>();
    cc.put(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
    assertNotNull(
        fencedPkce.authenticate(presented("crm", secret, cc)),
        "client_credentials unaffected by PKCE");
  }

  @AfterAll
  void stop() throws Exception {
    if (pool != null) pool.close();
    if (pg != null) pg.close();
  }
}
