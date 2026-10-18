package com.unipass.server;

import com.unipass.password.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
public class PasswordController {
    private final PasswordChangeService passwords;
    public PasswordController(PasswordChangeService passwords) { this.passwords = passwords; }
    public static final class PasswordRequest {
        @com.fasterxml.jackson.annotation.JsonProperty("old_password") @Size(min=1, max=1024) public char[] oldPassword;
        @com.fasterxml.jackson.annotation.JsonProperty("new_password") @Size(min=1, max=1024) public char[] newPassword;
        @com.fasterxml.jackson.annotation.JsonProperty("confirm_password") @Size(min=1, max=1024) public char[] confirmation;
        @Override public String toString() { return "PasswordRequest[REDACTED]"; }
    }
    @GetMapping("/api/session/csrf") Map<String,String> csrf(CsrfToken csrf) {
        return Map.of("header_name", csrf.getHeaderName(), "parameter_name", csrf.getParameterName(), "token", csrf.getToken());
    }
    @GetMapping({"/", "/api/session/me"}) Map<String,Object> me(@AuthenticationPrincipal IdentityPrincipal principal) {
        return Map.of("sub", principal.getUserId(), "auth_epoch", principal.getEpoch());
    }
    @PostMapping("/api/password/change") ResponseEntity<PasswordOperation> change(@AuthenticationPrincipal IdentityPrincipal principal,
            @RequestHeader("Idempotency-Key") String key, @Valid @RequestBody PasswordRequest request) {
        AuthenticatedActor actor = AuthenticatedActor.user(principal.getUserId(), principal.getEpoch(), principal.getAuthenticatedAt());
        PasswordOperation operation = passwords.change(actor, key, request.oldPassword, request.newPassword, request.confirmation);
        return ResponseEntity.status(operation.state() == PasswordOperation.State.UNKNOWN || operation.state() == PasswordOperation.State.PREPARED ? 202 : 200).body(operation);
    }
    @GetMapping("/api/password/operations/{id}") PasswordOperation status(@AuthenticationPrincipal IdentityPrincipal principal, @PathVariable("id") UUID id) {
        return passwords.get(id, principal.getUserId());
    }
}
