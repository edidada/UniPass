package com.test.examples.unipass.server;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.*;

/**
 * Accepts any recorded previous client secret while its own overlap window is open. The built-in
 * provider always runs first and owns the current secret; this provider only participates when the
 * presented secret failed there, so a rotation never locks a client out during rollout. Successive
 * rotations keep multiple generations, each with its original deadline; expired entries are ignored
 * on read and removed by the rotation transaction.
 */
final class PreviousClientSecretAuthenticationProvider implements AuthenticationProvider {
  private static final PasswordEncoder ENCODER =
      PasswordEncoderFactories.createDelegatingPasswordEncoder();
  private final RegisteredClientRepository clients;
  private final JdbcTemplate jdbc;
  private final Clock clock;

  PreviousClientSecretAuthenticationProvider(
      RegisteredClientRepository clients, JdbcTemplate jdbc, Clock clock) {
    this.clients = clients;
    this.jdbc = jdbc;
    this.clock = clock;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) authentication;
    if (!Set.of(
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
            ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .contains(token.getClientAuthenticationMethod())) return null;
    if (!(token.getPrincipal() instanceof String clientId) || clientId.isBlank()) return null;
    if (!(token.getCredentials() instanceof String secret) || secret.isBlank()) return null;
    RegisteredClient client = clients.findByClientId(clientId);
    if (client == null
        || !client.getClientAuthenticationMethods().contains(token.getClientAuthenticationMethod()))
      return null;
    List<String> previous =
        jdbc.queryForList(
            "SELECT secret_hash FROM oauth_client_secret_previous WHERE client_id=? AND valid_until>?",
            String.class,
            clientId,
            Timestamp.from(clock.instant()));
    for (String hash : previous) {
      boolean matches;
      try {
        matches = ENCODER.matches(secret, hash);
      } catch (IllegalArgumentException malformed) {
        matches = false;
      }
      if (matches)
        return new OAuth2ClientAuthenticationToken(
            client, token.getClientAuthenticationMethod(), token.getCredentials());
    }
    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
