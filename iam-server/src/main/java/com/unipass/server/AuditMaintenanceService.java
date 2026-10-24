package com.unipass.server;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Privileged audit retention operations. Manual archive/restore require
 * ROLE_SYSTEM_ADMIN plus recent password and MFA, and both write their own
 * audit row in the same transaction. Read-only batch inspection follows the
 * auditor permission.
 */
@Service
public final class AuditMaintenanceService {
    private final AuditArchiveService archives;
    private final TransactionTemplate tx;
    private final AccountState accounts;
    private final MfaService mfa;
    private final AdminAuditService audit;
    private final Clock clock;

    public AuditMaintenanceService(AuditArchiveService archives, TransactionTemplate tx, AccountState accounts,
            MfaService mfa, AdminAuditService audit, Clock clock) {
        this.archives = archives; this.tx = tx; this.accounts = accounts; this.mfa = mfa; this.audit = audit; this.clock = clock;
    }

    public void requireStrong(IdentityPrincipal principal) {
        if (!accounts.roles(principal.getUserId()).contains("ROLE_SYSTEM_ADMIN")
                || !principal.hasRecentPassword(clock.instant()) || !mfa.recent(principal))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Administrative authority and recent password/MFA required");
    }

    public void requireAuditor(IdentityPrincipal principal) {
        List<String> roles = accounts.roles(principal.getUserId());
        if (!roles.contains("ROLE_SYSTEM_ADMIN") && !roles.contains("ROLE_ADMIN_AUDIT"))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Audit authority required");
    }

    public AuditArchiveService.Batch archive(IdentityPrincipal principal, Instant cutoff, int maxRows, String sourceIp) {
        requireStrong(principal);
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            AuditArchiveService.Batch batch = archives.archive(cutoff, maxRows);
            if (batch != null) audit.record("AUDIT_ARCHIVED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                    null, batch.id(), Map.of("batch_id", batch.id().toString(), "rows", Long.toString(batch.rows())), sourceIp);
            return batch;
        });
    }

    /** Scheduled archival has no interactive operator; it is still audited as the system actor. */
    public AuditArchiveService.Batch archiveDue(Instant cutoff, int maxRows) {
        return tx.execute(status -> {
            AuditArchiveService.Batch batch = archives.archive(cutoff, maxRows);
            if (batch != null) audit.record("AUDIT_ARCHIVED", "SUCCESS", null, null, null, null, batch.id(),
                    Map.of("batch_id", batch.id().toString(), "rows", Long.toString(batch.rows())));
            return batch;
        });
    }

    public List<AuditArchiveService.Batch> batches(IdentityPrincipal principal, int limit) {
        requireAuditor(principal);
        return archives.batches(limit);
    }

    public AuditArchiveService.Verification verify(IdentityPrincipal principal, java.util.UUID batchId) {
        requireAuditor(principal);
        return archives.verify(batchId);
    }

    public int restore(IdentityPrincipal principal, java.util.UUID batchId, String sourceIp) {
        requireStrong(principal);
        return tx.execute(status -> {
            accounts.lockAndRequire(principal);
            int restored = archives.restore(batchId);
            audit.record("AUDIT_RESTORED", "SUCCESS", principal.getUserId(), null, principal.getLoginId(),
                    null, batchId, Map.of("batch_id", batchId.toString(), "rows", Integer.toString(restored)), sourceIp);
            return restored;
        });
    }
}
