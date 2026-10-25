package com.unipass.server;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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
    private final MfaService mfa;
    private final ClientRegistrationService registration;
    private final Clock clock;
    private final Duration overlap;
    private final ObjectMapper json = new ObjectMapper();

    public ClientAdminService(RegisteredClientRepository clients, JdbcTemplate jdbc, TransactionTemplate tx, AccountState accounts,
            AdminAuditService audit, MfaService mfa, ClientRegistrationService registration, Clock clock, Environment env) {
        this.clients = clients; this.jdbc = jdbc; this.tx = tx; this.accounts = accounts; this.audit = audit;
        this.mfa = mfa;
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

    /** Enforces the application-admin role plus recent genuine password and recent MFA, matching the other privileged consoles. */
    private void requireRecentAuthority(IdentityPrincipal principal) {
        requireAppAdmin(principal);
        if (!principal.hasRecentPassword(clock.instant()) || !mfa.recent(principal))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Administrative authority and recent password/MFA required");
    }

    public record Registration(String clientId, String name, String kind, List<String> redirectUris,
            List<String> logoutRedirectUris, Set<String> scopes, String backchannelLogoutUri, String reason) {
        @Override public String toString() { return "Registration[REDACTED]"; }
    }

    /** secret is non-null only for confidential clients and is never persisted in clear text. */
    public record Issued(String id, String clientId, String secret, Instant previousSecretValidUntil) {
        @Override public String toString() { return "Issued[" + clientId + "]"; }
    }

    public record Summary(String id, String clientId, String name, String kind, boolean enabled, List<String> redirectUris,
            List<String> postLogoutRedirectUris, Set<String> scopes, String backchannelLogoutUri, Instant issuedAt) { }

    /** One immutable callback configuration snapshot, newest first when read. */
    public record CallbackHistory(String action, List<String> redirectUris, List<String> postLogoutRedirectUris,
            String backchannelLogoutUri, String reason, Instant createdAt) { }

    public List<Summary> list() {
        Map<String, Boolean> disabled = new HashMap<>();
        Set<String> deleted = new HashSet<>();
        jdbc.query("SELECT client_id,disabled,deleted_at IS NOT NULL AS deleted FROM oauth_client_status",
                (org.springframework.jdbc.core.RowCallbackHandler) r -> {
                    disabled.put(r.getString(1), r.getBoolean(2));
                    if (r.getBoolean(3)) deleted.add(r.getString(1));
                });
        List<Summary> all = new ArrayList<>();
        for (String id : jdbc.queryForList("SELECT client_id FROM oauth2_registered_client ORDER BY client_id", String.class)) {
            if (deleted.contains(id)) continue; // tombstones stay out of the management list
            RegisteredClient client = clients.findByClientId(id);
            if (client == null) continue;
            all.add(new Summary(client.getId(), client.getClientId(), client.getClientName(), kind(client),
                    !Boolean.TRUE.equals(disabled.get(id)),
                    client.getRedirectUris().stream().sorted().toList(),
                    client.getPostLogoutRedirectUris().stream().sorted().toList(),
                    new TreeSet<>(client.getScopes()),
                    String.valueOf(client.getClientSettings().getSetting("unipass.backchannel_logout_uri") == null ? "" : client.getClientSettings().getSetting("unipass.backchannel_logout_uri")),
                    client.getClientIdIssuedAt()));
        }
        return all;
    }

    /** Returns true when the client carries a soft-delete tombstone; used to block revival. */
    private boolean isDeleted(String clientId) {
        return Boolean.TRUE.equals(jdbc.query("SELECT deleted_at IS NOT NULL FROM oauth_client_status WHERE client_id=?",
                (org.springframework.jdbc.core.ResultSetExtractor<Boolean>) r -> r.next() ? r.getBoolean(1) : Boolean.FALSE, clientId));
    }

    /** Bounded, newest-first callback history for one live (not deleted) application. */
    public List<CallbackHistory> history(String clientId, int limit) {
        if (limit < 1 || limit > 100) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Page size out of range");
        if (clients.findByClientId(clientId) == null || isDeleted(clientId))
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Client unavailable");
        return jdbc.query("""
                SELECT action,redirect_uris::text AS redirect_uris,post_logout_redirect_uris::text AS logout_uris,
                       backchannel_logout_uri,reason,created_at
                FROM oauth_client_callback_history WHERE client_id=?
                ORDER BY created_at DESC,seq DESC LIMIT ?
                """, (r, n) -> new CallbackHistory(r.getString("action"), readUris(r.getString("redirect_uris")),
                readUris(r.getString("logout_uris")), r.getString("backchannel_logout_uri"), r.getString("reason"),
                r.getTimestamp("created_at").toInstant()), clientId, limit);
    }

    private void recordCallbacks(String clientId, String action, List<String> redirects, List<String> logoutRedirects,
            String backchannel, IdentityPrincipal principal, String reason) {
        jdbc.update("""
                INSERT INTO oauth_client_callback_history(id,client_id,action,redirect_uris,post_logout_redirect_uris,
                    backchannel_logout_uri,actor_id,reason,created_at)
                VALUES (?,?,?,?::jsonb,?::jsonb,?,?,?,?)
                """, UUID.randomUUID(), clientId, action, json(redirects), json(logoutRedirects),
                blankToNull(backchannel), principal.getUserId(), reason, Timestamp.from(clock.instant()));
    }

    private String json(List<String> values) {
        try { return json.writeValueAsString(values == null ? List.of() : values); }
        catch (Exception e) { throw new IllegalStateException("Callback history serialization failed"); }
    }

    private List<String> readUris(String raw) {
        try { return json.readValue(raw, new TypeReference<List<String>>() { }); }
        catch (Exception e) { throw new IllegalStateException("Stored callback history is invalid"); }
    }

    private static String blankToNull(String value) { return value == null || value.isBlank() ? null : value; }

    private static boolean callbacksChanged(RegisteredClient existing, ClientRegistrationService.Spec spec) {
        return !new HashSet<>(existing.getRedirectUris()).equals(new HashSet<>(spec.redirects()))
                || !new HashSet<>(existing.getPostLogoutRedirectUris()).equals(new HashSet<>(spec.logoutRedirects()))
                || !normalize((String) existing.getClientSettings().getSetting("unipass.backchannel_logout_uri"))
                        .equals(normalize(spec.backchannel()));
    }

    private static String normalize(String value) { return value == null ? "" : value; }

    /**
     * Soft-deletes an application: an irreversible tombstone is written, the client is
     * disabled, its active authorizations are revoked, and the action is audited. The
     * registration and audit rows are kept (no physical deletion). Replays of the same
     * idempotency key succeed without re-applying; a different reason on the same key or
     * any attempt on an already-deleted client conflicts.
     */
    public void delete(IdentityPrincipal principal, String clientId, String reason, String key) {
        delete(principal, clientId, reason, key, null);
    }

    public void delete(IdentityPrincipal principal, String clientId, String reason, String key, String sourceIp) {
        requireRecentAuthority(principal);
        requireReason(reason);
        if (key == null || !key.matches("[a-zA-Z0-9_-]{16,128}"))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Idempotency key required");
        tx.executeWithoutResult(status -> {
            accounts.lockAndRequire(principal);
            requireAppAdmin(principal);
            RegisteredClient client = locked(clientId);
            UUID actionId = UUID.randomUUID();
            boolean fresh = jdbc.update("""
                    INSERT INTO admin_client_action(id,actor_id,client_id,action,idempotency_key,reason,created_at)
                    VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING
                    """, actionId, principal.getUserId(), clientId, "DELETE", key, reason, Timestamp.from(clock.instant())) == 1;
            if (!fresh) {
                String stored = jdbc.query("""
                        SELECT reason FROM admin_client_action
                        WHERE actor_id=? AND client_id=? AND action=? AND idempotency_key=?
                        """, (org.springframework.jdbc.core.ResultSetExtractor<String>) r -> {
                    if (!r.next()) throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency context changed");
                    return r.getString(1);
                }, principal.getUserId(), clientId, "DELETE", key);
                if (!reason.equals(stored)) throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency context changed");
                return; // same key and reason: success without re-applying the change
            }
            // A different key reached deletion first; do not delete again.
            if (isDeleted(clientId)) throw new ResponseStatusException(HttpStatus.CONFLICT, "Client deleted");
            jdbc.update("""
                    INSERT INTO oauth_client_status(client_id,disabled,deleted_at,deleted_by,delete_reason,reason,updated_at)
                    VALUES (?,true,?,?,?,?,?) ON CONFLICT (client_id) DO UPDATE
                    SET disabled=true, deleted_at=excluded.deleted_at, deleted_by=excluded.deleted_by,
                        delete_reason=excluded.delete_reason, reason=COALESCE(oauth_client_status.reason, excluded.delete_reason),
                        updated_at=excluded.updated_at
                    """, clientId, Timestamp.from(clock.instant()), principal.getUserId(), reason, reason, Timestamp.from(clock.instant()));
            // Revoke the real authorization families using the locked registration id, not the client id.
            jdbc.update("UPDATE oauth2_authorization SET revoked=true WHERE registered_client_id=? AND revoked=false", client.getId());
            audit.record("CLIENT_DELETED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                    clientId, actionId, Map.of("client_id", clientId, "reason", reason), sourceIp);
        });
    }

    private static String kind(RegisteredClient client) {
        return !client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE) ? "CONFIDENTIAL"
                : Boolean.TRUE.equals(client.getClientSettings().getSetting("unipass.native")) ? "NATIVE" : "SPA";
    }

    public void update(IdentityPrincipal principal, String clientId, Registration spec, String reason) {
        update(principal, clientId, spec, reason, null);
    }

    public void update(IdentityPrincipal principal, String clientId, Registration spec, String reason, String sourceIp) {
        requireRecentAuthority(principal);
        requireReason(reason);
        if (spec == null || !clientId.equals(spec.clientId()))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client identifier is immutable");
        tx.executeWithoutResult(status -> {
            accounts.lockAndRequire(principal);
            requireAppAdmin(principal);
            RegisteredClient existing = locked(clientId);
            ClientRegistrationService.Kind kind;
            try { kind = ClientRegistrationService.Kind.valueOf(spec.kind()); }
            catch (RuntimeException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client kind required"); }
            if (!kind.name().equals(kind(existing)))
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client kind cannot change");
            var definition = new ClientRegistrationService.Spec(spec.clientId(), spec.name(), kind,
                    spec.redirectUris(), spec.logoutRedirectUris(), spec.scopes(), spec.backchannelLogoutUri());
            try { registration.validate(definition); }
            catch (IllegalArgumentException invalid) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client specification"); }
            var rebuilt = RegisteredClient.withId(existing.getId())
                    .clientId(existing.getClientId()).clientName(spec.name())
                    .clientIdIssuedAt(existing.getClientIdIssuedAt())
                    .clientSecret(existing.getClientSecret()).clientSecretExpiresAt(existing.getClientSecretExpiresAt());
            existing.getClientAuthenticationMethods().forEach(rebuilt::clientAuthenticationMethod);
            existing.getAuthorizationGrantTypes().forEach(rebuilt::authorizationGrantType);
            definition.redirects().forEach(rebuilt::redirectUri);
            definition.logoutRedirects().forEach(rebuilt::postLogoutRedirectUri);
            definition.scopes().forEach(rebuilt::scope);
            rebuilt.clientSettings(org.springframework.security.oauth2.server.authorization.settings.ClientSettings.builder()
                    .requireProofKey(existing.getClientSettings().isRequireProofKey())
                    .requireAuthorizationConsent(existing.getClientSettings().isRequireAuthorizationConsent())
                    .setting("unipass.native", existing.getClientSettings().getSetting("unipass.native"))
                    .setting("unipass.backchannel_logout_uri", spec.backchannelLogoutUri() == null ? "" : spec.backchannelLogoutUri()).build());
            rebuilt.tokenSettings(existing.getTokenSettings());
            clients.save(rebuilt.build());
            // Only actual callback changes create a new history row; a metadata-only edit does not.
            if (callbacksChanged(existing, definition))
                recordCallbacks(clientId, "UPDATE", definition.redirects(), definition.logoutRedirects(),
                        definition.backchannel(), principal, reason);
            audit.record("CLIENT_UPDATED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                    clientId, null, Map.of("client_id", clientId, "kind", kind.name()), sourceIp);
        });
    }

    /** Idempotent per key; a replay never re-applies the change (it cannot resurrect a later disable). */
    public void setEnabled(IdentityPrincipal principal, String clientId, boolean enabled, String reason, String key) {
        setEnabled(principal, clientId, enabled, reason, key, null);
    }

    public void setEnabled(IdentityPrincipal principal, String clientId, boolean enabled, String reason, String key, String sourceIp) {
        requireRecentAuthority(principal);
        requireReason(reason);
        if (key == null || !key.matches("[a-zA-Z0-9_-]{16,128}"))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Idempotency key required");
        tx.executeWithoutResult(status -> {
            accounts.lockAndRequire(principal);
            requireAppAdmin(principal);
            RegisteredClient client = locked(clientId);
            // A soft-deleted client can never be enabled or disabled again; deletion wins over enabled.
            if (isDeleted(clientId)) throw new ResponseStatusException(HttpStatus.CONFLICT, "Client deleted");
            String action = enabled ? "ENABLE" : "DISABLE";
            UUID actionId = UUID.randomUUID();
            boolean fresh = jdbc.update("""
                    INSERT INTO admin_client_action(id,actor_id,client_id,action,idempotency_key,reason,created_at)
                    VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING
                    """, actionId, principal.getUserId(), clientId, action, key, reason, Timestamp.from(clock.instant())) == 1;
            if (!fresh) {
                String stored = jdbc.query("""
                        SELECT reason FROM admin_client_action
                        WHERE actor_id=? AND client_id=? AND action=? AND idempotency_key=?
                        """, (org.springframework.jdbc.core.ResultSetExtractor<String>) r -> {
                    if (!r.next()) throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency context changed");
                    return r.getString(1);
                }, principal.getUserId(), clientId, action, key);
                if (!reason.equals(stored)) throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency context changed");
                return;
            }
            jdbc.update("""
                    INSERT INTO oauth_client_status(client_id,disabled,reason,updated_at) VALUES (?,?,?,?)
                    ON CONFLICT (client_id) DO UPDATE SET disabled=excluded.disabled,reason=excluded.reason,updated_at=excluded.updated_at
                    """, clientId, !enabled, reason, Timestamp.from(clock.instant()));
            if (!enabled) {
                // The V8 trigger enqueues back-channel logout for every newly revoked family.
                jdbc.update("UPDATE oauth2_authorization SET revoked=true WHERE registered_client_id=? AND revoked=false", client.getId());
            }
            audit.record(enabled ? "CLIENT_ENABLED" : "CLIENT_DISABLED", "SUCCESS", principal.getUserId(), null,
                    principal.getLoginId(), clientId, actionId, Map.of("client_id", clientId), sourceIp);
        });
    }

    private RegisteredClient locked(String clientId) {
        if (jdbc.queryForList("SELECT client_id FROM oauth2_registered_client WHERE client_id=? FOR UPDATE", String.class, clientId).isEmpty())
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Client unavailable");
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Client unavailable");
        return client;
    }

    public Issued register(IdentityPrincipal principal, Registration spec) {
        return register(principal, spec, null);
    }

    public Issued register(IdentityPrincipal principal, Registration spec, String sourceIp) {
        requireRecentAuthority(principal);
        requireReason(spec.reason());
        ClientRegistrationService.Kind kind;
        try { kind = ClientRegistrationService.Kind.valueOf(spec.kind()); }
        catch (RuntimeException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client kind required"); }
        String secret = kind == ClientRegistrationService.Kind.CONFIDENTIAL ? secret() : null;
        var definition = new ClientRegistrationService.Spec(spec.clientId(), spec.name(), kind,
                spec.redirectUris(), spec.logoutRedirectUris(), spec.scopes(), spec.backchannelLogoutUri());
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            requireAppAdmin(principal);
            String id;
            try { id = registration.register(definition, secret); }
            catch (IllegalStateException duplicate) { throw new ResponseStatusException(HttpStatus.CONFLICT, "Client already registered"); }
            catch (IllegalArgumentException invalid) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client specification"); }
            recordCallbacks(spec.clientId(), "REGISTER", spec.redirectUris(), spec.logoutRedirectUris(),
                    spec.backchannelLogoutUri(), principal, spec.reason());
            audit.record("CLIENT_REGISTERED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                    spec.clientId(), null, Map.of("client_id", spec.clientId(), "kind", kind.name()), sourceIp);
            return new Issued(id, spec.clientId(), secret, null);
        });
    }

    public Issued rotate(IdentityPrincipal principal, String clientId, String reason, String key) {
        return rotate(principal, clientId, reason, key, null);
    }

    public Issued rotate(IdentityPrincipal principal, String clientId, String reason, String key, String sourceIp) {
        requireRecentAuthority(principal);
        requireReason(reason);
        if (key == null || !key.matches("[a-zA-Z0-9_-]{16,128}"))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Idempotency key required");
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            requireAppAdmin(principal);
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
                    clientId, actionId, Map.of("client_id", clientId, "previous_secret_valid_until", until.toString()), sourceIp);
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
