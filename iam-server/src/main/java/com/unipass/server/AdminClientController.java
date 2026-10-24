package com.unipass.server;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/admin/console/clients")
public final class AdminClientController {
    private final ClientAdminService clients;
    public AdminClientController(ClientAdminService clients) { this.clients = clients; }

    @GetMapping
    List<ClientAdminService.Summary> list(@AuthenticationPrincipal IdentityPrincipal principal) {
        clients.requireAppAdmin(principal);
        return clients.list();
    }

    @PostMapping
    ClientAdminService.Issued register(@AuthenticationPrincipal IdentityPrincipal principal, @RequestBody ClientAdminService.Registration registration) {
        return clients.register(principal, registration);
    }

    @PostMapping("/{clientId}/rotate")
    ClientAdminService.Issued rotate(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable String clientId,
            @RequestHeader("Idempotency-Key") String key, @RequestBody Rotation rotation) {
        return clients.rotate(principal, clientId, rotation.reason, key);
    }

    @PutMapping("/{clientId}") @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    void update(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable String clientId,
            @RequestBody ClientAdminService.Registration registration) {
        clients.update(principal, clientId, registration, registration.reason());
    }

    @PostMapping("/{clientId}/state") @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    void state(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable String clientId,
            @RequestHeader("Idempotency-Key") String key, @RequestBody StateChange change) {
        clients.setEnabled(principal, clientId, change.enabled, change.reason, key);
    }

    public static final class Rotation {
        @com.fasterxml.jackson.annotation.JsonProperty("reason") public String reason;
        @Override public String toString() { return "Rotation[REDACTED]"; }
    }

    public static final class StateChange {
        @com.fasterxml.jackson.annotation.JsonProperty("enabled") public boolean enabled;
        @com.fasterxml.jackson.annotation.JsonProperty("reason") public String reason;
        @Override public String toString() { return "StateChange[REDACTED]"; }
    }
}
