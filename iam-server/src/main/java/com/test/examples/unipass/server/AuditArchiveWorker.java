package com.test.examples.unipass.server;

import java.time.Duration;
import java.time.Instant;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduled retention enforcement. Disabled by default; when enabled it moves rows older than the
 * configured retention window in bounded batches so a long backlog never holds one large
 * transaction.
 */
@Component
@ConditionalOnProperty(name = "unipass.audit.archive.enabled", havingValue = "true")
public final class AuditArchiveWorker {
  private static final int BATCH = 1000;
  private static final org.slf4j.Logger LOG =
      org.slf4j.LoggerFactory.getLogger(AuditArchiveWorker.class);
  private final AuditMaintenanceService maintenance;
  private final Duration retention;
  private final ArchiveElection election;

  public AuditArchiveWorker(
      AuditMaintenanceService maintenance, Environment env, ArchiveElection election) {
    this.maintenance = maintenance;
    this.election = election;
    Duration configured;
    try {
      configured = env.getProperty("unipass.audit.retention", Duration.class, Duration.ofDays(180));
    } catch (RuntimeException invalid) {
      throw new IllegalArgumentException("Invalid audit retention window");
    }
    if (configured.compareTo(Duration.ofDays(30)) < 0)
      throw new IllegalArgumentException("Audit retention must be at least 30 days");
    this.retention = configured;
  }

  @Scheduled(
      fixedDelayString = "${unipass.audit.archive.interval:PT30M}",
      initialDelayString = "${unipass.audit.archive.initial-delay:PT1M}")
  public void run() {
    try {
      // Only one instance archives at a time; the loser skips this tick.
      election.tryRun(this::archiveBatches);
    } catch (RuntimeException unavailable) {
      LOG.warn("Audit archival unavailable");
    }
  }

  private void archiveBatches() {
    Instant cutoff = Instant.now().minus(retention);
    for (int batch = 0; batch < 20; batch++) {
      var archived = maintenance.archiveDue(cutoff, BATCH);
      if (archived == null || archived.rows() < BATCH) return;
    }
  }
}
