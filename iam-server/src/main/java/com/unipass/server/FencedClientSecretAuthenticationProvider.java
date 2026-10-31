package com.unipass.server;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Fences confidential-client authentication on the live disabled state so that a just-disabled or
 * just-rotated client can never still authenticate. The whole check runs inside a single
 * transaction that first takes a row lock on {@code oauth2_registered_client} (serializing it with
 * the disable / rotate transactions) and only then reads {@code oauth_client_status}. Because the
 * lock is held until the transaction commits, a disable that commits after the entry filter passed
 * can no longer race a token being issued against the old state.
 *
 * <p>Both the current secret and the single open previous-secret overlap window are verified with
 * the delegating password encoder (never a concatenation of hashes). PKCE is checked by
 * re-implementing the framework {@code CodeVerifierAuthenticator} semantics against the stored
 * authorization, so the standard authorization_code grant stays protocol-correct and is never
 * relaxed or skipped.
 *
 * <p>The provider is registered ahead of the framework's {@code ClientSecretAuthenticationProvider}
 * and only acts on {@code client_secret_basic} / {@code client_secret_post}; every other method
 * (public {@code none}, JWT assertions) falls through to the default providers. Unknown clients
 * return {@code null} so the framework still produces the canonical {@code invalid_client}
 * response.
 */
final class FencedClientSecretAuthenticationProvider implements AuthenticationProvider {
  private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE =
      new OAuth2TokenType(OAuth2ParameterNames.CODE);
  private static final String ERROR_URI =
      "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";
  private final RegisteredClientRepository clients;
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final OAuth2AuthorizationService authorizations;
  private final Clock clock;
  private final PasswordEncoder encoder =
      PasswordEncoderFactories.createDelegatingPasswordEncoder();

  FencedClientSecretAuthenticationProvider(
      RegisteredClientRepository clients,
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      OAuth2AuthorizationService authorizations,
      Clock clock) {
    this.clients = clients;
    this.jdbc = jdbc;
    this.tx = tx;
    this.authorizations = authorizations;
    this.clock = clock;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) authentication;
    ClientAuthenticationMethod method = token.getClientAuthenticationMethod();
    if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)
        && !ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method)) return null;
    if (!(token.getPrincipal() instanceof String clientId) || clientId.isBlank()) return null;
    if (!(token.getCredentials() instanceof String secret) || secret.isBlank()) return null;
    // This provider runs inside the ambient /oauth/token transaction opened by
    // TokenTransactionFilter. We must NOT start a nested REQUIRED transaction here:
    // an OAuth2AuthenticationException raised by fence(...) would mark that outer
    // transaction rollback-only, and when the outer filter later commits it throws
    // UnexpectedRollbackException, which TokenTransactionFilter turns into a 503.
    // When an outer transaction is already active, run fence(...) directly so the
    // row lock is held by that ambient transaction until the token is issued
    // (preserving the fence semantics) and the thrown exception stays clean for SAS
    // to translate into 401/400. We deliberately avoid REQUIRES_NEW, which would
    // release the lock before the token is issued and break the fence. Only when
    // called with no active transaction (direct unit tests, other endpoints) do we
    // open our own transaction via tx.execute.
    if (TransactionSynchronizationManager.isActualTransactionActive()) {
      return fence(clientId, secret, token);
    }
    return tx.execute(status -> fence(clientId, secret, token));
  }

  /**
   * Runs entirely inside the provider's transaction so the row lock serializes with disable/rotate.
   */
  private Authentication fence(
      String clientId, String secret, OAuth2ClientAuthenticationToken token) {
    // 1. Take the registered-client row lock first. No row means an unknown client:
    //    return null so the framework's provider yields the canonical invalid_client.
    if (jdbc.queryForList(
            "SELECT id FROM oauth2_registered_client WHERE client_id=? FOR UPDATE",
            String.class,
            clientId)
        .isEmpty()) return null;
    // 2. Only now read the disabled flag. Missing row is treated as enabled (lock order:
    //    registered row first, then status; never reversed, to avoid deadlocks with disable).
    boolean disabled =
        jdbc.query(
            "SELECT disabled FROM oauth_client_status WHERE client_id=?",
            (org.springframework.jdbc.core.ResultSetExtractor<Boolean>)
                r -> r.next() && r.getBoolean(1),
            clientId);
    if (disabled) throw invalidClient();
    RegisteredClient client = clients.findByClientId(clientId);
    if (client == null) throw invalidClient();
    if (!client.getClientAuthenticationMethods().contains(token.getClientAuthenticationMethod()))
      throw invalidClient();
    // 3. Verify the current secret, falling back to the open previous-secret window.
    boolean matchCurrent =
        client.getClientSecret() != null && encoder.matches(secret, client.getClientSecret());
    boolean matchPrevious = false;
    if (!matchCurrent) {
      for (String hash :
          jdbc.queryForList(
              "SELECT secret_hash FROM oauth_client_secret_previous WHERE client_id=? AND valid_until>?",
              String.class,
              clientId,
              Timestamp.from(clock.instant()))) {
        try {
          if (encoder.matches(secret, hash)) {
            matchPrevious = true;
            break;
          }
        } catch (IllegalArgumentException malformed) {
          /* ignore a corrupted stored hash */
        }
      }
    }
    if (!matchCurrent && !matchPrevious) throw invalidClient();
    // 4. Reject expired secrets.
    Instant expiresAt = client.getClientSecretExpiresAt();
    if (expiresAt != null && clock.instant().isAfter(expiresAt)) throw invalidClient();
    // 5. PKCE for the authorization_code grant (parity with the framework verifier).
    verifyCodeVerifier(token, client);
    // 6. Opportunistically re-encode a weakened current secret.
    if (matchCurrent && encoder.upgradeEncoding(client.getClientSecret()))
      clients.save(RegisteredClient.from(client).clientSecret(encoder.encode(secret)).build());
    return new OAuth2ClientAuthenticationToken(
        client, token.getClientAuthenticationMethod(), token.getCredentials());
  }

  /** Parity port of the framework CodeVerifierAuthenticator for confidential clients. */
  private void verifyCodeVerifier(
      OAuth2ClientAuthenticationToken clientAuthentication, RegisteredClient registeredClient) {
    Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
    if (!authorizationCodeGrant(parameters)) return;
    OAuth2Authorization authorization =
        authorizations.findByToken(
            (String) parameters.get(OAuth2ParameterNames.CODE), AUTHORIZATION_CODE_TOKEN_TYPE);
    if (authorization == null) throw invalidGrant(OAuth2ParameterNames.CODE);
    OAuth2AuthorizationRequest request =
        authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
    if (request == null) throw invalidGrant(OAuth2ParameterNames.CODE);
    String codeChallenge =
        (String) request.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE);
    String codeVerifier = (String) parameters.get(PkceParameterNames.CODE_VERIFIER);
    if (codeChallenge == null || codeChallenge.isBlank()) {
      if (registeredClient.getClientSettings().isRequireProofKey()
          || codeVerifier != null && !codeVerifier.isBlank())
        throw invalidGrant(PkceParameterNames.CODE_CHALLENGE);
      return;
    }
    String method =
        (String) request.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD);
    if (!codeVerifierValid(codeVerifier, codeChallenge, method))
      throw invalidGrant(PkceParameterNames.CODE_VERIFIER);
  }

  private static boolean authorizationCodeGrant(Map<String, Object> parameters) {
    if (!"authorization_code".equals(parameters.get(OAuth2ParameterNames.GRANT_TYPE))) return false;
    if (parameters.get(OAuth2ParameterNames.CODE) == null
        || ((String) parameters.get(OAuth2ParameterNames.CODE)).isBlank())
      throw invalidGrant(OAuth2ParameterNames.CODE);
    return true;
  }

  private static boolean codeVerifierValid(
      String codeVerifier, String codeChallenge, String codeChallengeMethod) {
    if (codeVerifier == null || codeVerifier.isBlank()) return false;
    if ("S256".equals(codeChallengeMethod)) {
      try {
        byte[] digest =
            MessageDigest.getInstance("SHA-256")
                .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest).equals(codeChallenge);
      } catch (java.security.NoSuchAlgorithmException e) {
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
      }
    }
    return false;
  }

  private static OAuth2AuthenticationException invalidClient() {
    return new OAuth2AuthenticationException(
        new OAuth2Error(
            OAuth2ErrorCodes.INVALID_CLIENT, "Client authentication failed", ERROR_URI));
  }

  private static OAuth2AuthenticationException invalidGrant(String parameter) {
    return new OAuth2AuthenticationException(
        new OAuth2Error(
            OAuth2ErrorCodes.INVALID_GRANT, "Client authentication failed: " + parameter, null));
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
