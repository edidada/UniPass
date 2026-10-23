package com.unipass.server;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.util.List;

/**
 * Browser management API for the T8 application lifecycle. Reads require the
 * live application authority; every write is idempotent by key, audited in the
 * same transaction and guarded by recent password plus recent MFA.
 */
@RestController
@RequestMapping("/api/admin/console/clients")
public final class ClientManagementController {
    private final ClientManagementService clients;

    public ClientManagementController(ClientManagementService clients) { this.clients = clients; }

    @GetMapping
    ClientManagementService.ListPage list(@AuthenticationPrincipal IdentityPrincipal principal,
            @RequestParam(required = false) String cursor, @RequestParam(defaultValue = "50") int limit) {
        clients.requireAppAdmin(principal);
        return clients.list(cursor, limit);
    }

    @GetMapping("/{clientId}")
    ClientManagementService.ClientDetail detail(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable String clientId) {
        clients.requireAppAdmin(principal);
        if (!clientId.matches("[A-Za-z0-9_.-]{3,100}")) throw pathInvalid();
        return clients.detail(clientId);
    }

    public static final class RegisterRequest {
        @com.fasterxml.jackson.annotation.JsonProperty("client_id") public String clientId;
        public String name;
        public String kind;
        @com.fasterxml.jackson.annotation.JsonProperty("redirect_uris") public List<String> redirectUris;
        @com.fasterxml.jackson.annotation.JsonProperty("post_logout_redirect_uris") public List<String> postLogoutRedirectUris;
        public List<String> scopes;
        @com.fasterxml.jackson.annotation.JsonProperty("backchannel_logout_uri") public String backchannelUri;
        public String owner;
        @Override public String toString() { return "RegisterRequest[REDACTED]"; }
    }

    @PostMapping("/register") @ResponseStatus(HttpStatus.CREATED)
    ClientManagementService.IssuedSecret register(@AuthenticationPrincipal IdentityPrincipal principal,
            @RequestHeader("Idempotency-Key") String key, @RequestBody RegisterRequest request) {
        requireKey(key);
        return clients.register(principal, spec(request), key, reason(null));
    }

    @PostMapping("/{clientId}/update")
    ClientManagementService.ClientDetail update(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable String clientId,
            @RequestHeader("Idempotency-Key") String key, @RequestBody ClientManagementService.UpdateRequest update) {
        requireKey(key);
        if (!clientId.matches("[A-Za-z0-9_.-]{3,100}")) throw pathInvalid();
        return clients.update(principal, clientId, update, key, reason(null));
    }

    public static final class StateRequest {
        public String reason;
        @Override public String toString() { return "StateRequest[REDACTED]"; }
    }

    @PostMapping("/{clientId}/disable") @ResponseStatus(HttpStatus.OK)
    ClientManagementService.ClientReview disable(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable String clientId,
            @RequestHeader("Idempotency-Key") String key, @RequestBody StateRequest request) {
        requireKey(key);
        if (!clientId.matches("[A-Za-z0-9_.-]{3,100}")) throw pathInvalid();
        return clients.setState(principal, clientId, false, key, reason(request == null ? null : request.reason));
    }

    @PostMapping("/{clientId}/enable")
    ClientManagementService.ClientReview enable(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable String clientId,
            @RequestHeader("Idempotency-Key") String key, @RequestBody StateRequest request) {
        requireKey(key);
        if (!clientId.matches("[A-Za-z0-9_.-]{3,100}")) throw pathInvalid();
        return clients.setState(principal, clientId, true, key, reason(request == null ? null : request.reason));
    }

    @PostMapping("/{clientId}/rotate-secret")
    ClientManagementService.IssuedSecret rotate(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable String clientId,
            @RequestHeader("Idempotency-Key") String key, @RequestBody ClientManagementService.RotationRequest request) {
        requireKey(key);
        if (!clientId.matches("[A-Za-z0-9_.-]{3,100}")) throw pathInvalid();
        return clients.rotate(principal, clientId, request, key, reason(null));
    }

    static void requireKey(String key) {
        if (key == null || !key.matches("[a-zA-Z0-9_-]{16,128}"))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Idempotency key required");
    }

    private static String reason(String explicit) {
        String reason = explicit == null || explicit.isBlank() ? "" : explicit;
        if (reason.length() > 500 || reason.codePoints().anyMatch(Character::isISOControl))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Reason required");
        return reason;
    }

    private static ClientRegistrationService.Spec spec(RegisterRequest request) {
        if (request == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid client specification");
        ClientRegistrationService.Kind kind = null;
        if (request.kind != null) try { kind = ClientRegistrationService.Kind.valueOf(request.kind); } catch (IllegalArgumentException e) { /* rejected below */ }
        return new ClientRegistrationService.Spec(request.clientId, request.name, kind, request.redirectUris,
                request.postLogoutRedirectUris, request.scopes, request.backchannelUri, request.owner);
    }

    private static ResponseStatusException pathInvalid() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client identifier invalid");
    }
}
