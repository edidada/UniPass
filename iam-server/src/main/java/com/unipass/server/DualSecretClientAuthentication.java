package com.unipass.server;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * T8 confidential client authentication with the bounded dual-secret rotation
 * window. Registered ahead of the framework ClientSecretAuthenticationProvider:
 * a presented secret is matched against the current verifier and, only inside
 * its explicit overlap window, against the retired verifier; both checks use
 * the delegating password encoder (never a concatenation of hashes). The
 * validation is fenced by a row lock on oauth2_registered_client, so
 * disable/update/rotation and token issuance serialize per client and a just
 * disabled client can never authenticate again. The PKCE code_verifier checks
 * mirror the framework CodeVerifierAuthenticator (upstream Apache-2.0) so the
 * standard confidential grant stays protocol-correct.
 */
public final class DualSecretClientAuthentication implements AuthenticationProvider {
    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";
    private final RegisteredClientRepository clients;
    private final OAuth2AuthorizationService authorizations;
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    public DualSecretClientAuthentication(RegisteredClientRepository clients, OAuth2AuthorizationService authorizations, JdbcTemplate jdbc, Clock clock) {
        this.clients = clients; this.authorizations = authorizations; this.jdbc = jdbc; this.clock = clock;
    }

    /** Persisted verifier state; carries hashes and ids only, never the clear secret. */
    record Verifiers(boolean enabled, String current, String previous, Instant previousUntil) { }

    Verifiers verifiers(String clientId) {
        List<Verifiers> rows = jdbc.query("""
                SELECT enabled, client_secret, secret_previous, secret_previous_until
                FROM oauth2_registered_client WHERE client_id=? FOR UPDATE
                """, (r, n) -> new Verifiers(r.getBoolean("enabled"), r.getString("client_secret"),
                r.getString("secret_previous"), orNull(r.getTimestamp("secret_previous_until"), "secret_previous_until")), clientId);
        return rows.isEmpty() ? null : rows.get(0);
    }

    private static Instant orNull(Timestamp timestamp, String column) { return timestamp == null ? null : timestamp.toInstant(); }

    @Override public Authentication authenticate(Authentication authentication) {
        var clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;
        if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(clientAuthentication.getClientAuthenticationMethod())
                && !ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientAuthentication.getClientAuthenticationMethod())) return null;
        String clientId = clientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = clients.findByClientId(clientId);
        if (registeredClient == null) return null;
        Verifiers stored = verifiers(clientId);
        if (stored == null) return null;
        if (!registeredClient.getClientAuthenticationMethods().contains(clientAuthentication.getClientAuthenticationMethod()))
            throwInvalidClient("authentication_method");
        if (clientAuthentication.getCredentials() == null) throwInvalidClient("credentials");
        String presented = clientAuthentication.getCredentials().toString();
        boolean matchCurrent = stored.current() != null && encoder.matches(presented, stored.current());
        boolean withinWindow = stored.previous() != null && stored.previousUntil() != null && clock.instant().isBefore(stored.previousUntil());
        boolean matchPrevious = withinWindow && encoder.matches(presented, stored.previous());
        // Enabling state always wins over both verifiers; a disabled client is rejected
        // without distinguishing reasons so disabling closes every live credential path.
        if (!stored.enabled() || (!matchCurrent && !matchPrevious)) throwInvalidClient("client_secret");
        if (registeredClient.getClientSecretExpiresAt() != null && clock.instant().isAfter(registeredClient.getClientSecretExpiresAt()))
            throwInvalidClient("client_secret_expires_at");
        if (matchCurrent && encoder.upgradeEncoding(stored.current())) {
            clients.save(RegisteredClient.from(registeredClient).clientSecret(encoder.encode(presented)).build());
        }
        verifyCodeVerifier(clientAuthentication, registeredClient);
        return new OAuth2ClientAuthenticationToken(registeredClient, clientAuthentication.getClientAuthenticationMethod(),
                clientAuthentication.getCredentials());
    }

    @Override public boolean supports(Class<?> authentication) { return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication); }

    /** Parity port of the framework CodeVerifierAuthenticator for confidential clients. */
    private void verifyCodeVerifier(OAuth2ClientAuthenticationToken clientAuthentication, RegisteredClient registeredClient) {
        Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
        if (!authorizationCodeGrant(parameters)) return;
        OAuth2Authorization authorization = authorizations.findByToken((String) parameters.get(OAuth2ParameterNames.CODE), AUTHORIZATION_CODE_TOKEN_TYPE);
        if (authorization == null) throwInvalidGrant(OAuth2ParameterNames.CODE);
        OAuth2AuthorizationRequest request = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        String codeChallenge = (String) request.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE);
        String codeVerifier = (String) parameters.get(PkceParameterNames.CODE_VERIFIER);
        if (codeChallenge == null || codeChallenge.isBlank()) {
            if (registeredClient.getClientSettings().isRequireProofKey() || codeVerifier != null && !codeVerifier.isBlank())
                throwInvalidGrant(PkceParameterNames.CODE_CHALLENGE);
            return;
        }
        String method = (String) request.getAdditionalParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD);
        if (!codeVerifierValid(codeVerifier, codeChallenge, method)) throwInvalidGrant(PkceParameterNames.CODE_VERIFIER);
    }

    private static boolean authorizationCodeGrant(Map<String, Object> parameters) {
        if (!"authorization_code".equals(parameters.get(OAuth2ParameterNames.GRANT_TYPE))) return false;
        if (parameters.get(OAuth2ParameterNames.CODE) == null || ((String) parameters.get(OAuth2ParameterNames.CODE)).isBlank())
            throwInvalidGrant(OAuth2ParameterNames.CODE);
        return true;
    }

    private static boolean codeVerifierValid(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
        if (codeVerifier == null || codeVerifier.isBlank()) return false;
        if ("S256".equals(codeChallengeMethod)) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                return Base64.getUrlEncoder().withoutPadding().encodeToString(digest).equals(codeChallenge);
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, null, null));
            }
        }
        return false;
    }

    private static void throwInvalidClient(String parameter) {
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                "Client authentication failed: " + parameter, ERROR_URI));
    }

    private static void throwInvalidGrant(String parameter) {
        throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                "Client authentication failed: " + parameter, null));
    }
}
