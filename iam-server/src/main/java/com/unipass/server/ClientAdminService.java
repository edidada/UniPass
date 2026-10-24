package com.unipass.server;

import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;

/**
 * Application (OAuth client) management for the T8 console: listing,
 * registration with a once-shown generated secret, and rotation that keeps the
 * previous secret valid for a bounded overlap window.
 */
@Service
public final class ClientAdminService {
    private static final SecureRandom RANDOM = new SecureRandom();
    static final Duration DEFAULT_OVERLAP = Duration.ofHours(24);
    static final Duration MAX_OVERLAP = Duration.ofDays(7);
    private final RegisteredClientRepository clients;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AccountState accounts;
    private final AdminAuditService audit;
    private final ClientRegistrationService registration;
    private final Clock clock;
    private final Duration overlap;

    public ClientAdminService(RegisteredClientRepository clients, JdbcTemplate jdbc, TransactionTemplate tx, AccountState accounts,
            AdminAuditService audit, ClientRegistrationService registration, Clock clock, Environment env) {
        this.clients = clients; this.jdbc = jdbc; this.tx = tx; this.accounts = accounts; this.audit = audit;
        this.registration = registration; this.clock = clock;
        Duration configured;
        try { configured = env.getProperty("unipass.clients.secret-rotation-window", Duration.class, DEFAULT_OVERLAP); }
        catch (RuntimeException e) { throw new IllegalArgumentException("Invalid client secret rotation window"); }
        if (configured.compareTo(Duration.ofMinutes(1)) < 0 || configured.compareTo(MAX_OVERLAP) > 0)
            throw new IllegalArgumentException("Client secret rotation window must be between 1 minute and 7 days");
        this.overlap = configured;
    }

    public void requireAppAdmin(IdentityPrincipal principal) {
        List<String> roles = accounts.roles(principal.getUserId());
        if (!roles.contains("ROLE_SYSTEM_ADMIN") && !roles.contains("ROLE_ADMIN_APP"))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Application administration required");
    }

    public record Registration(String clientId, String name, String kind, List<String> redirectUris,
            List<String> logoutRedirectUris, Set<String> scopes, String backchannelLogoutUri, String reason) {
        @Override public String toString() { return "Registration[REDACTED]"; }
    }

    /** secret is non-null only for confidential clients and is never persisted in clear text. */
    public record Issued(String id, String clientId, String secret, Instant previousSecretValidUntil) {
        @Override public String toString() { return "Issued[" + clientId + "]"; }
    }

    public record Summary(String id, String clientId, String name, String kind, List<String> redirectUris,
            List<String> postLogoutRedirectUris, Set<String> scopes, Instant issuedAt) { }

    public List<Summary> list() {
        List<Summary> all = new ArrayList<>();
        for (String id : jdbc.queryForList("SELECT client_id FROM oauth2_registered_client ORDER BY client_id", String.class)) {
            RegisteredClient client = clients.findByClientId(id);
            if (client == null) continue;
            String kind = !client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE) ? "CONFIDENTIAL"
                    : Boolean.TRUE.equals(client.getClientSettings().getSetting("unipass.native")) ? "NATIVE" : "SPA";
            all.add(new Summary(client.getId(), client.getClientId(), client.getClientName(), kind,
                    client.getRedirectUris().stream().sorted().toList(),
                    client.getPostLogoutRedirectUris().stream().sorted().toList(),
                    new TreeSet<>(client.getScopes()), client.getClientIdIssuedAt()));
        }
        return all;
    }

    public Issued register(IdentityPrincipal principal, Registration spec) {
        requireAppAdmin(principal);
        requireReason(spec.reason());
        ClientRegistrationService.Kind kind;
        try { kind = ClientRegistrationService.Kind.valueOf(spec.kind()); }
        catch (RuntimeException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client kind required"); }
        String secret = kind == ClientRegistrationService.Kind.CONFIDENTIAL ? secret() : null;
        var definition = new ClientRegistrationService.Spec(spec.clientId(), spec.name(), kind,
                spec.redirectUris(), spec.logoutRedirectUris(), spec.scopes(), spec.backchannelLogoutUri());
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            String id;
            try { id = registration.register(definition, secret); }
            catch (IllegalStateException duplicate) { throw new ResponseStatusException(HttpStatus.CONFLICT, "Client already registered"); }
            catch (IllegalArgumentException invalid) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client specification"); }
            audit.record("CLIENT_REGISTERED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                    spec.clientId(), null, Map.of("client_id", spec.clientId(), "kind", kind.name()));
            return new Issued(id, spec.clientId(), secret, null);
        });
    }

    public Issued rotate(IdentityPrincipal principal, String clientId, String reason, String key) {
        requireAppAdmin(principal);
        requireReason(reason);
        if (key == null || !key.matches("[a-zA-Z0-9_-]{16,128}"))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Idempotency key required");
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            // Serialize rotations per client; the row lock also guarantees the previous
            // hash we read below is the current secret at commit time.
            if (jdbc.queryForList("SELECT client_id FROM oauth2_registered_client WHERE client_id=? FOR UPDATE", String.class, clientId).isEmpty())
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Client unavailable");
            RegisteredClient client = clients.findByClientId(clientId);
            if (client == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Client unavailable");
            if (!client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client has no rotatable secret");
            UUID actionId = UUID.randomUUID();
            boolean fresh = jdbc.update("""
                    INSERT INTO admin_client_action(id,actor_id,client_id,action,idempotency_key,reason,created_at)
                    VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING
                    """, actionId, principal.getUserId(), clientId, "ROTATE", key, reason, Timestamp.from(clock.instant())) == 1;
            if (!fresh) throw new ResponseStatusException(HttpStatus.CONFLICT, "Secret already issued for this idempotency key");
            Instant now = clock.instant();
            Instant until = now.plus(overlap);
            jdbc.update("""
                    INSERT INTO oauth_client_secret_previous(client_id,secret_hash,valid_until,created_at)
                    VALUES (?,?,?,?) ON CONFLICT (client_id) DO UPDATE
                    SET secret_hash=excluded.secret_hash,valid_until=excluded.valid_until,created_at=excluded.created_at
                    """, clientId, client.getClientSecret(), Timestamp.from(until), Timestamp.from(now));
            String secret = secret();
            clients.save(RegisteredClient.from(client).clientSecret(
                    PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(secret)).build());
            audit.record("CLIENT_SECRET_ROTATED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                    clientId, actionId, Map.of("client_id", clientId, "previous_secret_valid_until", until.toString()));
            return new Issued(client.getId(), clientId, secret, until);
        });
    }

    private static String secret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void requireReason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 500 || reason.codePoints().anyMatch(Character::isISOControl))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Reason required");
    }

    Duration overlap() { return overlap; }
}
