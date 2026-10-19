package com.unipass.server;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.security.authentication.BadCredentialsException;
import java.util.*;

@Service
public class AccountState {
    private final JdbcTemplate jdbc;
    private final RedisSecurityState security;
    public AccountState(JdbcTemplate jdbc,RedisSecurityState security) { this.jdbc = jdbc; this.security=security; }
    public record Snapshot(UUID id, String directoryId, String type, long epoch, boolean active, boolean mustChange) { }
    public Snapshot byEmployee(String employee) {
        security.requireReady();
        List<Snapshot> rows = jdbc.query("SELECT * FROM iam_user WHERE employee_no=?", (r,n) -> new Snapshot(
                r.getObject("id", UUID.class), r.getString("directory_id"), r.getString("directory_type"), r.getLong("auth_epoch"),
                "ACTIVE".equals(r.getString("status")) && "OPEN".equals(r.getString("password_gate")), r.getBoolean("must_change_password")), employee);
        return rows.isEmpty() ? null : rows.get(0);
    }
    public boolean allowed(UUID id, long epoch) {
        var observed=security.current();
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_user WHERE id=? AND status='ACTIVE' AND password_gate='OPEN' AND auth_epoch=? AND EXISTS(SELECT 1 FROM auth_runtime_state WHERE singleton AND redis_generation=?::uuid AND redis_run_id=?))", Boolean.class, id, epoch,observed.generation(),observed.runId()));
    }
    public boolean mustChange(UUID id) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT must_change_password FROM iam_user WHERE id=?", Boolean.class, id));
    }
    public void lockAndRequire(UUID id, long epoch) {
        var observed=security.current();
        List<Boolean> rows = jdbc.query("SELECT status='ACTIVE' AND password_gate='OPEN' AND auth_epoch=? AND EXISTS(SELECT 1 FROM auth_runtime_state WHERE singleton AND redis_generation=?::uuid AND redis_run_id=?) FROM iam_user WHERE id=? FOR UPDATE", (r,n) -> r.getBoolean(1), epoch,observed.generation(),observed.runId(),id);
        if (rows.isEmpty() || !rows.get(0)) throw new BadCredentialsException("Account unavailable");
    }
    public List<String> roles(UUID id) {
        List<String> roles = new ArrayList<>(jdbc.queryForList("SELECT role FROM iam_user_role WHERE user_id=?", String.class, id));
        roles.add("ROLE_USER"); return roles;
    }
    public void audit(UUID user, String action) {
        jdbc.update("INSERT INTO auth_audit(id,user_id,action,trace_id) VALUES (?,?,?,?)", UUID.randomUUID(), user, action, UUID.randomUUID());
    }
    public boolean recoveryStatusAllowed(IdentityPrincipal principal, String operationId) {
        var observed=security.current();
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM password_operation p JOIN iam_user u ON u.id=p.user_id WHERE p.id=?::uuid AND u.id=? AND u.status='ACTIVE' AND u.auth_epoch=p.fenced_epoch AND p.fenced_epoch=? AND EXISTS(SELECT 1 FROM auth_runtime_state WHERE singleton AND redis_generation=?::uuid AND redis_run_id=?))",
                Boolean.class, operationId, principal.getUserId(), principal.getEpoch() + 1,observed.generation(),observed.runId()));
    }
}
