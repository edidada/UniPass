package com.unipass.server;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.util.*;

@RestController
@RequestMapping("/api/admin/console")
public final class AdminConsoleController {
    private final AdminConsoleService console;
    private final AdminAuditService audit;
    private final TrustedProxy proxies;

    public AdminConsoleController(AdminConsoleService console, AdminAuditService audit, TrustedProxy proxies) {
        this.console = console; this.audit = audit; this.proxies = proxies;
    }

    @GetMapping("/audit")
    AdminAuditService.Page audit(@AuthenticationPrincipal IdentityPrincipal principal,
            @RequestParam(required = false) String cursor, @RequestParam(defaultValue = "50") int limit) {
        console.requireAuditor(principal);
        if (limit < 1 || limit > 100) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Page size out of range");
        try { return audit.page(cursor, limit); }
        catch (IllegalArgumentException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cursor rejected"); }
    }

    @GetMapping(value = "/audit/export", produces = "text/csv")
    String export(@AuthenticationPrincipal IdentityPrincipal principal) {
        console.requireAuditor(principal);
        return String.join("\n", audit.export(1000)) + "\n";
    }

    @GetMapping("/users/{id}/roles")
    List<String> roles(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable UUID id) {
        console.requireConsole(principal);
        return console.roles(id);
    }

    public static final class RoleChange {
        @com.fasterxml.jackson.annotation.JsonProperty("action") public String action;
        @com.fasterxml.jackson.annotation.JsonProperty("role") public String role;
        @com.fasterxml.jackson.annotation.JsonProperty("reason") public String reason;
        @Override public String toString() { return "RoleChange[REDACTED]"; }
    }

    @PostMapping("/users/{id}/roles") @ResponseStatus(HttpStatus.NO_CONTENT)
    void change(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable UUID id,
            @RequestHeader("Idempotency-Key") String key, @RequestBody RoleChange change,
            jakarta.servlet.http.HttpServletRequest request) {
        if (key == null || !key.matches("[a-zA-Z0-9_-]{16,128}"))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Idempotency key required");
        console.change(principal, id, change.action, change.role, change.reason, key, proxies.resolve(request));
    }
}
