package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * T8 application/client lifecycle management. Every mutation requires
 * ROLE_APP_ADMIN or ROLE_SYSTEM_ADMIN (live check per request, re-checked under
 * the actor row lock inside the transaction to close the role-only TOCTOU
 * window), recent real password plus recent MFA, a reason, an idempotency key
 * and a same-transaction audit record. Registration/update reuse the single
 * ClientRegistrationService validator (no second, weaker policy). Secrets are
 * generated cryptographically random, shown once, and stored only as password
 * hashes; rotation keeps a bounded explicit overlap between verifiers and the
 * disabled state always wins over both keys.
 */
@Service
public final class ClientManagementService {
    static final String KIND_CONFIDENTIAL = "CONFIDENTIAL", KIND_NATIVE = "NATIVE", KIND_SPA = "SPA";
    static final int LIST_MAX = 100, OWNER_MIN = 4, OWNER_MAX = 200, OVERLAP_MAX = 3600;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AccountState accounts;
    private final AdminAuditService audit;
    private final MfaService mfa;
    private final Clock clock;
    private final ClientRegistrationService registrations;
    private final RegisteredClientRepository clients;
    private final ObjectMapper mapper = new ObjectMapper();

    public ClientManagementService(JdbcTemplate jdbc, TransactionTemplate tx, AccountState accounts, AdminAuditService audit,
            MfaService mfa, Clock clock, ClientRegistrationService registrations, RegisteredClientRepository clients) {
        this.jdbc = jdbc; this.tx = tx; this.accounts = accounts; this.audit = audit; this.mfa = mfa;
        this.clock = clock; this.registrations = registrations; this.clients = clients;
    }

    /* ---------- authority ---------- */

    void requireAppAdmin(IdentityPrincipal principal) {
        // Live membership: never the roles frozen inside the login session.
        if (!AdminAuthorities.any(accounts.roles(principal.getUserId()), AdminAuthorities.CLIENT_MANAGE))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Application authority required");
    }

    private void requireRecentProof(IdentityPrincipal principal) {
        if (!principal.hasRecentPassword(clock.instant()) || !mfa.recent(principal))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Recent password and MFA required");
    }

    private void requireReason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 500 || reason.codePoints().anyMatch(Character::isISOControl))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Reason required");
    }

    /* ---------- views ---------- */

    public record ClientSummary(String id, String clientId, String name, String kind, String owner, boolean enabled,
            boolean confidential, Instant issuedAt) { }
    public record ClientDetail(String id, String clientId, String name, String kind, String owner, boolean enabled,
            boolean confidential, List<String> redirectUris, List<String> postLogoutRedirectUris, List<String> scopes,
            String backchannelUri, String secretKeyId, String previousSecretKeyId, Instant overlapUntil) { }
    /** Cleartext secret appears in a single successful response; the toString never carries it. */
    public record IssuedSecret(String registeredId, String clientId, String secretKeyId, String secret, boolean replay,
            Instant overlapUntil, String guidance) {
        @Override public String toString() { return "IssuedSecret[REDACTED]"; }
    }
    public record ClientReview(String clientId, boolean enabled, boolean replay) { }
    public record UpdateRequest(String name, String owner, List<String> redirectUris, List<String> postLogoutRedirectUris,
            List<String> scopes, String backchannelUri) {
        @Override public String toString() { return "UpdateRequest[REDACTED]"; }
    }
    public record RotationRequest(Integer overlapSeconds) {
        @Override public String toString() { return "RotationRequest[REDACTED]"; }
    }
    public record ListPage(List<ClientSummary> entries, String nextCursor) { }

    record ClientCursor(Instant at, String clientId) {
        static ClientCursor parse(String raw) {
            if (raw == null || raw.isBlank()) return null;
            if (!raw.matches("[A-Za-z0-9_-]{16,512}")) throw cursorRejected();
            try {
                String[] parts = new String(Base64.getUrlDecoder().decode(raw), StandardCharsets.UTF_8).split("\\|", -1);
                if (parts.length != 2) throw new IllegalArgumentException();
                return new ClientCursor(Instant.parse(parts[0]), parts[1]);
            } catch (RuntimeException e) { throw cursorRejected(); }
        }
        static String encode(ClientCursor cursor) {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString((cursor.at().toString() + "|" + cursor.clientId()).getBytes(StandardCharsets.UTF_8));
        }
    }

    private static ResponseStatusException cursorRejected() { return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cursor rejected"); }

    /* ---------- reads ---------- */

    public ListPage list(String cursor, int limit) {
        if (limit < 1 || limit > LIST_MAX) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Page size out of range");
        ClientCursor decoded = ClientCursor.parse(cursor);
        List<ClientSummary> rows = jdbc.query("""
                SELECT id,client_id,client_name,enabled,client_id_issued_at,client_authentication_methods,client_settings
                FROM oauth2_registered_client
                WHERE (?::timestamptz IS NULL OR (client_id_issued_at,client_id) < (?::timestamptz,?))
                ORDER BY client_id_issued_at DESC, client_id DESC LIMIT ?
                """, (r, n) -> new ClientSummary(r.getString("id"), r.getString("client_id"), r.getString("client_name"),
                kind(r.getString("client_authentication_methods"), r.getString("client_settings")),
                owner(r.getString("client_settings")), r.getBoolean("enabled"),
                r.getString("client_authentication_methods") != null && r.getString("client_authentication_methods").contains("client_secret_basic"),
                r.getTimestamp("client_id_issued_at") == null ? null : r.getTimestamp("client_id_issued_at").toInstant()),
                decoded == null ? null : decoded.at(), decoded == null ? null : decoded.at(),
                decoded == null ? null : decoded.clientId(), limit);
        String next = null;
        if (rows.size() == limit && !rows.isEmpty()) {
            ClientSummary last = rows.get(rows.size() - 1);
            next = ClientCursor.encode(new ClientCursor(last.issuedAt(), last.clientId()));
        }
        return new ListPage(rows, next);
    }

    public ClientDetail detail(String clientId) {
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null) throw unavailable();
        record SecretRow(boolean enabled, String keyId, String previousKeyId, Instant until) { }
        List<SecretRow> secret = jdbc.query("""
                SELECT enabled,secret_key_id,secret_previous_key_id,secret_previous_until FROM oauth2_registered_client
                WHERE client_id=?
                """, (r, n) -> new SecretRow(r.getBoolean("enabled"), r.getString("secret_key_id"),
                r.getString("secret_previous_key_id"),
                r.getTimestamp("secret_previous_until") == null ? null : r.getTimestamp("secret_previous_until").toInstant()),
                clientId);
        if (secret.isEmpty()) throw unavailable();
        SecretRow row = secret.get(0);
        return new ClientDetail(client.getId(), client.getClientId(), client.getClientName(), kindOf(client),
                owner(client.getClientSettings().getSettings()), row.enabled(),
                client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                List.copyOf(client.getRedirectUris()), List.copyOf(client.getPostLogoutRedirectUris()),
                List.copyOf(client.getScopes()),
                Objects.toString(client.getClientSettings().getSetting("unipass.backchannel_logout_uri"), ""),
                row.keyId(), row.previousKeyId(), row.until());
    }

    static String owner(Map<String, Object> settings) {
        Object value = settings.get("unipass.owner");
        return value == null ? null : value.toString();
    }

    static String kindOf(RegisteredClient client) {
        if (client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE))
            return Boolean.TRUE.equals(client.getClientSettings().getSetting("unipass.native")) ? KIND_NATIVE : KIND_SPA;
        return KIND_CONFIDENTIAL;
    }

    private static String kind(String methods, String settingsJson) {
        if (methods != null && methods.contains("client_secret_basic")) return KIND_CONFIDENTIAL;
        if (settingsJson != null && settingsJson.contains("\"unipass.native\":true")) return KIND_NATIVE;
        return KIND_SPA;
    }

    private static ResponseStatusException unavailable() { return new ResponseStatusException(HttpStatus.NOT_FOUND, "Client unavailable"); }

    /* ---------- register ---------- */

    public IssuedSecret register(IdentityPrincipal principal, ClientRegistrationService.Spec spec, String key, String reason) {
        requireReason(reason);
        requireRecentProof(principal);
        try { registrations.validate(spec, true); }
        catch (IllegalArgumentException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client specification"); }
        final String digest = digest(spec);
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            // Closed TOCTOU: the application authority is re-checked under the actor
            // and registration locks, so a concurrent revocation still rejects.
            if (!AdminAuthorities.any(accounts.roles(principal.getUserId()), AdminAuthorities.CLIENT_MANAGE))
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Application authority required");
            boolean fresh = action(principal.getUserId(), spec.clientId(), "REGISTER", digest, key, reason) == 1;
            if (fresh) {
                if (clients.findByClientId(spec.clientId()) != null)
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "Client already registered");
                String secret = randomSecret();
                RegisteredClient client = registrations.builder(spec,
                        org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(secret));
                clients.save(client);
                String keyId = randomKeyId();
                jdbc.update("UPDATE oauth2_registered_client SET secret_key_id=? WHERE client_id=?", keyId, spec.clientId());
                audit.record("CLIENT_REGISTERED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                        spec.clientId(), UUID.randomUUID(),
                        Map.of("client", spec.clientId(), "key_id", keyId, "reason", reason.trim()));
                return new IssuedSecret(client.getId(), spec.clientId(), keyId, secret, false, null,
                        "Save the secret now; it is never displayed again.");
            }
            // Lost-response replay: never re-expose the one-time secret; the identical
            // request context is required and the answer is a read-only confirmation.
            sameContext(principal.getUserId(), spec.clientId(), "REGISTER", digest, key, reason);
            RegisteredClient existing = clients.findByClientId(spec.clientId());
            if (existing == null) throw new ResponseStatusException(HttpStatus.CONFLICT, "Client registration incomplete");
            String keyId = jdbc.queryForObject("SELECT secret_key_id FROM oauth2_registered_client WHERE client_id=?", String.class, spec.clientId());
            return new IssuedSecret(existing.getId(), spec.clientId(), keyId, null, true, null,
                    "The secret was shown once; rotate again with a new idempotency key if it is lost.");
        });
    }

    /* ---------- update ---------- */

    public ClientDetail update(IdentityPrincipal principal, String clientId, UpdateRequest update, String key, String reason) {
        requireReason(reason);
        requireRecentProof(principal);
        final ClientRegistrationService.Spec request = specOf(clientId, update);
        try { registrations.validate(request, true); }
        catch (IllegalArgumentException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client specification"); }
        final String digest = digest(update);
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            if (!AdminAuthorities.any(accounts.roles(principal.getUserId()), AdminAuthorities.CLIENT_MANAGE))
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Application authority required");
            RegisteredClient existing = locked(clientId);
            if (existing == null) throw unavailable();
            boolean fresh = action(principal.getUserId(), clientId, "UPDATE", digest, key, reason) == 1;
            if (fresh) {
                var settings = ClientSettings.withSettings(existing.getClientSettings().getSettings())
                        .setting("unipass.owner", request.owner());
                RegisteredClient changed = RegisteredClient.from(existing)
                        .clientName(request.name())
                        .redirectUri(uris -> { uris.clear(); uris.addAll(request.redirects()); })
                        .postLogoutRedirectUri(uris -> { uris.clear(); uris.addAll(request.logoutRedirects()); })
                        .scope(allowed -> { allowed.clear(); allowed.addAll(request.scopes()); })
                        .clientSettings(settings.build()).build();
                clients.save(changed);
                audit.record("CLIENT_UPDATED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                        clientId, UUID.randomUUID(), Map.of("client", clientId, "reason", reason.trim()));
            } else {
                sameContext(principal.getUserId(), clientId, "UPDATE", digest, key, reason);
            }
            return detail(clientId);
        });
    }

    /* ---------- enable / disable ---------- */

    public ClientReview setState(IdentityPrincipal principal, String clientId, boolean enable, String key, String reason) {
        requireReason(reason);
        requireRecentProof(principal);
        final String digest = digest(enable);
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            if (!AdminAuthorities.any(accounts.roles(principal.getUserId()), AdminAuthorities.CLIENT_MANAGE))
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Application authority required");
            RegisteredClient client = locked(clientId);
            if (client == null) throw unavailable();
            boolean fresh = action(principal.getUserId(), clientId, enable ? "ENABLE" : "DISABLE", digest, key, reason) == 1;
            if (fresh) {
                jdbc.update("UPDATE oauth2_registered_client SET enabled=? WHERE id=?", enable, client.getId());
                if (!enable) {
                    // Revoke every authorization of this client in the same transaction; the
                    // framework trigger enqueues backchannel logout tasks, and a disabled
                    // client's pending (and just-enqueued) tasks are fenced, never delivered.
                    jdbc.update("UPDATE oauth2_authorization SET revoked=true WHERE registered_client_id=?", client.getId());
                    jdbc.update("UPDATE oidc_logout_task SET state='DEAD',finished_at=? WHERE client_id=? AND state IN ('PENDING','RUNNING')",
                            Timestamp.from(clock.instant()), client.getClientId());
                    audit.record("CLIENT_DISABLED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                            clientId, UUID.randomUUID(), Map.of("client", clientId, "reason", reason.trim()));
                } else {
                    audit.record("CLIENT_ENABLED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                            clientId, UUID.randomUUID(), Map.of("client", clientId, "reason", reason.trim()));
                }
            } else {
                sameContext(principal.getUserId(), clientId, enable ? "ENABLE" : "DISABLE", digest, key, reason);
            }
            boolean enabled = jdbc.queryForObject("SELECT enabled FROM oauth2_registered_client WHERE id=?", Boolean.class, client.getId());
            return new ClientReview(clientId, enabled, !fresh);
        });
    }

    /* ---------- secret rotation ---------- */

    public IssuedSecret rotate(IdentityPrincipal principal, String clientId, RotationRequest request, String key, String reason) {
        requireReason(reason);
        requireRecentProof(principal);
        if (request == null || request.overlapSeconds() == null || request.overlapSeconds() < 0 || request.overlapSeconds() > OVERLAP_MAX)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Overlap window required");
        final String digest = digest(request.overlapSeconds());
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            if (!AdminAuthorities.any(accounts.roles(principal.getUserId()), AdminAuthorities.CLIENT_MANAGE))
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Application authority required");
            RegisteredClient client = locked(clientId);
            if (client == null) throw unavailable();
            // Public clients can never gain a secret or confidential authentication.
            if (!client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client is not confidential");
            record VerifierRow(String hash, String keyId) { }
            VerifierRow current = jdbc.query("""
                    SELECT client_secret,secret_key_id FROM oauth2_registered_client WHERE id=? FOR UPDATE
                    """, (r, n) -> new VerifierRow(r.getString("client_secret"), r.getString("secret_key_id")), client.getId()).get(0);
            boolean fresh = action(principal.getUserId(), clientId, "ROTATE", digest, key, reason) == 1;
            if (fresh) {
                String secret = randomSecret();
                String hash = org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(secret);
                String keyId = randomKeyId();
                Instant until = clock.instant().plusSeconds(request.overlapSeconds());
                // Rotation retires the directly previous verifier only; older material can
                // neither be restored nor extended by a later rotation.
                jdbc.update("""
                        UPDATE oauth2_registered_client SET client_secret=?,secret_key_id=?,secret_previous=?,secret_previous_key_id=?,secret_previous_until=?
                        WHERE id=?
                        """, hash, keyId, current.hash(), current.keyId(), Timestamp.from(until), client.getId());
                audit.record("CLIENT_SECRET_ROTATED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                        clientId, UUID.randomUUID(), Map.of("client", clientId, "key_id", keyId,
                                "overlap", String.valueOf(request.overlapSeconds()), "reason", reason.trim()));
                return new IssuedSecret(client.getId(), clientId, keyId, secret, false,
                        request.overlapSeconds() > 0 ? until : null, "Save the secret now; it is never displayed again.");
            }
            sameContext(principal.getUserId(), clientId, "ROTATE", digest, key, reason);
            String keyId = jdbc.queryForObject("SELECT secret_key_id FROM oauth2_registered_client WHERE id=?", String.class, client.getId());
            return new IssuedSecret(client.getId(), clientId, keyId, null, true, overlapUntil(client.getId()),
                    "The secret was shown once; rotate again with a new idempotency key if it is lost.");
        });
    }

    private Instant overlapUntil(String id) {
        Timestamp until = jdbc.query("SELECT secret_previous_until FROM oauth2_registered_client WHERE id=? FOR UPDATE",
                rs -> rs.next() ? rs.getTimestamp("secret_previous_until") : null, id);
        return until == null ? null : until.toInstant();
    }

    /* ---------- helpers ---------- */

    private int action(UUID actor, String clientId, String verb, String digest, String key, String reason) {
        return jdbc.update("""
                INSERT INTO iam_client_action(id,actor_id,registered_client_id,action,request_digest,idempotency_key,reason,created_at)
                VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING
                """, UUID.randomUUID(), actor, clientId, verb, digest, key, reason, Timestamp.from(clock.instant()));
    }

    private void sameContext(UUID actor, String clientId, String verb, String digest, String key, String reason) {
        String stored = jdbc.query("""
                SELECT reason FROM iam_client_action
                WHERE actor_id=? AND registered_client_id=? AND action=? AND request_digest=? AND idempotency_key=?
                """, (rs, n) -> { if (!rs.next()) throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency context changed"); return rs.getString(1); },
                actor, clientId, verb, digest, key);
        if (!reason.equals(stored)) throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency context changed");
    }

    private static String randomSecret() {
        byte[] bytes = new byte[32]; RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String randomKeyId() {
        byte[] bytes = new byte[8]; RANDOM.nextBytes(bytes);
        return "sk-" + HexFormat.of().formatHex(bytes);
    }

    private String digest(Object value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapper.writeValueAsBytes(value)));
        } catch (Exception e) { throw new IllegalStateException("Request digest failed"); }
    }

    /** Builds the specification used to re-validate an update against the client's fixed type. */
    private ClientRegistrationService.Spec specOf(String clientId, UpdateRequest update) {
        RegisteredClient existing = clients.findByClientId(clientId);
        var kind = existing == null ? ClientRegistrationService.Kind.CONFIDENTIAL : ClientRegistrationService.Kind.valueOf(kindOf(existing));
        return new ClientRegistrationService.Spec(clientId, update.name(), kind, update.redirectUris(),
                update.postLogoutRedirectUris(), update.scopes(), update.backchannelUri(), update.owner());
    }

    /** Loads and row-locks the registration for serialized lifecycle writes. */
    private RegisteredClient locked(String clientId) {
        List<String> ids = jdbc.query("SELECT id FROM oauth2_registered_client WHERE client_id=? FOR UPDATE",
                (r, n) -> r.getString("id"), clientId);
        return ids.isEmpty() ? null : clients.findById(ids.get(0));
    }
}
