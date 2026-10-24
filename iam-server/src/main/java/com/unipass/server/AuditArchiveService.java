package com.unipass.server;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * Moves audit rows older than the retention cutoff into audit_archive and keeps
 * a per-batch SHA-256 digest so a restore can prove integrity first. Rows are
 * moved (not deleted), and a restore is idempotent.
 */
@Service
public final class AuditArchiveService {
    public record Batch(UUID id, Instant cutoff, long rows, String digest, Instant createdAt) { }
    public record Verification(UUID id, long rows, boolean intact) { }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final Clock clock;

    public AuditArchiveService(JdbcTemplate jdbc, TransactionTemplate tx, Clock clock) {
        this.jdbc = jdbc; this.tx = tx; this.clock = clock;
    }

    /** Moves at most maxRows rows older than cutoff. Returns null when nothing matched. */
    public Batch archive(Instant cutoff, int maxRows) {
        if (cutoff == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Retention cutoff required");
        if (maxRows < 1 || maxRows > 10_000) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Batch size out of range");
        return tx.execute(status -> {
            UUID batchId = UUID.randomUUID();
            Timestamp at = Timestamp.from(clock.instant());
            int moved = jdbc.update("""
                    WITH candidates AS (
                        SELECT id FROM auth_audit WHERE created_at < ? ORDER BY created_at, id LIMIT ?
                    ), moved AS (
                        DELETE FROM auth_audit a USING candidates c WHERE a.id=c.id RETURNING a.*
                    )
                    INSERT INTO audit_archive(id,user_id,action,trace_id,login_id,result,client_id,source_ip,operation_id,detail,created_at,archived_at,batch_id)
                    SELECT id,user_id,action,trace_id,login_id,result,client_id,source_ip,operation_id,detail,created_at,?,? FROM moved
                    """, Timestamp.from(cutoff), maxRows, at, batchId);
            if (moved == 0) return null;
            String digest = digest(batchId);
            jdbc.update("INSERT INTO audit_archive_batch(id,cutoff,rows,digest,created_at) VALUES (?,?,?,?,?)",
                    batchId, Timestamp.from(cutoff), moved, digest, at);
            return new Batch(batchId, cutoff, moved, digest, at.toInstant());
        });
    }

    public List<Batch> batches(int limit) {
        if (limit < 1 || limit > 100) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Page size out of range");
        return jdbc.query("SELECT id,cutoff,rows,digest,created_at FROM audit_archive_batch ORDER BY created_at DESC, id DESC LIMIT ?",
                (r, n) -> new Batch(r.getObject("id", UUID.class), r.getTimestamp("cutoff").toInstant(),
                        r.getLong("rows"), r.getString("digest"), r.getTimestamp("created_at").toInstant()), limit);
    }

    /** Recomputes the digest from the stored rows; a mismatch means the archive was altered. */
    public Verification verify(UUID batchId) {
        Batch batch = batch(batchId);
        String current = digest(batchId);
        return new Verification(batchId, batch.rows(), current.equals(batch.digest()));
    }

    /** Restores an intact batch into auth_audit; already-present rows are skipped (idempotent). */
    public int restore(UUID batchId) {
        Batch batch = batch(batchId);
        if (!digest(batchId).equals(batch.digest()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Archive integrity check failed");
        return tx.execute(status -> jdbc.update("""
                INSERT INTO auth_audit(id,user_id,action,trace_id,login_id,result,client_id,source_ip,operation_id,detail,created_at)
                SELECT id,user_id,action,trace_id,login_id,result,client_id,source_ip,operation_id,detail,created_at
                FROM audit_archive WHERE batch_id=? ORDER BY created_at, id
                ON CONFLICT (id) DO NOTHING
                """, batchId));
    }

    private Batch batch(UUID batchId) {
        List<Batch> rows = jdbc.query("SELECT id,cutoff,rows,digest,created_at FROM audit_archive_batch WHERE id=?",
                (r, n) -> new Batch(r.getObject("id", UUID.class), r.getTimestamp("cutoff").toInstant(),
                        r.getLong("rows"), r.getString("digest"), r.getTimestamp("created_at").toInstant()), batchId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Archive batch unavailable");
        return rows.get(0);
    }

    private String digest(UUID batchId) {
        MessageDigest sha;
        try { sha = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
        jdbc.query("""
                SELECT id,user_id,action,trace_id,login_id,result,client_id,source_ip,operation_id,detail::text AS detail,created_at
                FROM audit_archive WHERE batch_id=? ORDER BY created_at, id
                """, r -> {
            String line = String.join("\u001f",
                    r.getString("id"), String.valueOf(r.getObject("user_id", UUID.class)), r.getString("action"),
                    r.getString("trace_id"), String.valueOf(r.getObject("login_id", UUID.class)), r.getString("result"),
                    String.valueOf(r.getString("client_id")), String.valueOf(r.getString("source_ip")),
                    String.valueOf(r.getObject("operation_id", UUID.class)), r.getString("detail"),
                    r.getTimestamp("created_at").toInstant().toString());
            sha.update(line.getBytes(StandardCharsets.UTF_8));
            sha.update((byte) '\n');
        }, batchId);
        StringBuilder hex = new StringBuilder(64);
        for (byte value : sha.digest()) hex.append(String.format("%02x", value));
        return hex.toString();
    }
}
