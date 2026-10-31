package com.test.examples.unipass.server;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/console/clients")
public final class AdminClientController {
  private final ClientAdminService clients;
  private final TrustedProxy proxies;

  public AdminClientController(ClientAdminService clients, TrustedProxy proxies) {
    this.clients = clients;
    this.proxies = proxies;
  }

  @GetMapping
  List<ClientAdminService.Summary> list(@AuthenticationPrincipal IdentityPrincipal principal) {
    clients.requireAppAdmin(principal);
    return clients.list();
  }

  @GetMapping("/{clientId}/history")
  List<ClientAdminService.CallbackHistory> history(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable String clientId,
      @RequestParam(defaultValue = "20") int limit) {
    clients.requireAppAdmin(principal);
    return clients.history(clientId, limit);
  }

  @GetMapping("/{clientId}/rotation-window")
  ClientAdminService.RotationWindow rotationWindow(
      @AuthenticationPrincipal IdentityPrincipal principal, @PathVariable String clientId) {
    clients.requireAppAdmin(principal);
    return clients.rotationWindow(clientId);
  }

  @PostMapping("/{clientId}/rotation-window")
  ClientAdminService.RotationWindow setRotationWindow(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable String clientId,
      @RequestHeader("Idempotency-Key") String key,
      @RequestBody RotationWindowRequest body,
      HttpServletRequest request) {
    clients.requireAppAdmin(principal);
    return clients.setRotationWindow(
        principal, clientId, body.seconds, body.reason, key, proxies.resolve(request));
  }

  @PostMapping
  ClientAdminService.Issued register(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @RequestBody ClientAdminService.Registration registration,
      HttpServletRequest request) {
    return clients.register(principal, registration, proxies.resolve(request));
  }

  @PostMapping("/{clientId}/rotate")
  ClientAdminService.Issued rotate(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable String clientId,
      @RequestHeader("Idempotency-Key") String key,
      @RequestBody Rotation rotation,
      HttpServletRequest request) {
    return clients.rotate(principal, clientId, rotation.reason, key, proxies.resolve(request));
  }

  @PutMapping("/{clientId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  void update(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable String clientId,
      @RequestBody ClientAdminService.Registration registration,
      HttpServletRequest request) {
    clients.update(
        principal, clientId, registration, registration.reason(), proxies.resolve(request));
  }

  @PostMapping("/{clientId}/state")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  void state(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable String clientId,
      @RequestHeader("Idempotency-Key") String key,
      @RequestBody StateChange change,
      HttpServletRequest request) {
    clients.setEnabled(
        principal, clientId, change.enabled, change.reason, key, proxies.resolve(request));
  }

  @PostMapping("/{clientId}/delete")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  void delete(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable String clientId,
      @RequestHeader("Idempotency-Key") String key,
      @RequestBody DeleteRequest body,
      HttpServletRequest request) {
    clients.delete(principal, clientId, body.reason, key, proxies.resolve(request));
  }

  public static final class Rotation {
    @com.fasterxml.jackson.annotation.JsonProperty("reason")
    public String reason;

    @Override
    public String toString() {
      return "Rotation[REDACTED]";
    }
  }

  public static final class StateChange {
    @com.fasterxml.jackson.annotation.JsonProperty("enabled")
    public boolean enabled;

    @com.fasterxml.jackson.annotation.JsonProperty("reason")
    public String reason;

    @Override
    public String toString() {
      return "StateChange[REDACTED]";
    }
  }

  public static final class DeleteRequest {
    @com.fasterxml.jackson.annotation.JsonProperty("reason")
    public String reason;

    @Override
    public String toString() {
      return "DeleteRequest[REDACTED]";
    }
  }

  public static final class RotationWindowRequest {
    @com.fasterxml.jackson.annotation.JsonProperty("seconds")
    public Integer seconds;

    @com.fasterxml.jackson.annotation.JsonProperty("reason")
    public String reason;

    @Override
    public String toString() {
      return "RotationWindowRequest[REDACTED]";
    }
  }
}
