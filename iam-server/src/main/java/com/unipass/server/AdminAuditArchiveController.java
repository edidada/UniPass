package com.unipass.server;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/console/audit/archive")
public final class AdminAuditArchiveController {
  private final AuditMaintenanceService maintenance;
  private final TrustedProxy proxies;

  public AdminAuditArchiveController(AuditMaintenanceService maintenance, TrustedProxy proxies) {
    this.maintenance = maintenance;
    this.proxies = proxies;
  }

  @GetMapping
  List<AuditArchiveService.Batch> batches(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @RequestParam(defaultValue = "20") int limit) {
    return maintenance.batches(principal, limit);
  }

  public static final class ArchiveRequest {
    @com.fasterxml.jackson.annotation.JsonProperty("cutoff")
    public Instant cutoff;

    @com.fasterxml.jackson.annotation.JsonProperty("max_rows")
    public int maxRows = 1000;

    @Override
    public String toString() {
      return "ArchiveRequest[REDACTED]";
    }
  }

  @PostMapping
  @ResponseStatus(HttpStatus.OK)
  AuditArchiveService.Batch archive(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @RequestBody ArchiveRequest request,
      HttpServletRequest servletRequest) {
    return maintenance.archive(
        principal, request.cutoff, request.maxRows, proxies.resolve(servletRequest));
  }

  @GetMapping("/{batchId}")
  AuditArchiveService.Verification verify(
      @AuthenticationPrincipal IdentityPrincipal principal, @PathVariable UUID batchId) {
    return maintenance.verify(principal, batchId);
  }

  @PostMapping("/{batchId}/restore")
  Restored restore(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable UUID batchId,
      HttpServletRequest request) {
    return new Restored(maintenance.restore(principal, batchId, proxies.resolve(request)));
  }

  public record Restored(int restored) {}
}
