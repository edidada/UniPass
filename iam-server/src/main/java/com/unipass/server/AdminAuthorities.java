package com.unipass.server;

import java.util.List;
import java.util.Set;

/**
 * T8 independent management authorities (least-privilege matrix).
 *
 * Each authority must be granted explicitly by ROLE_SYSTEM_ADMIN administration
 * (console or offline AdminRoleCli); no role silently implies another one, and
 * the narrowly scoped password/MFA recovery roles stay independent (they are
 * not members of this matrix and are never inferred from it). Checks always
 * consult the live iam_user_role rows for the acting identity, never the roles
 * captured inside the login session (TOCTOU), and privileged transactions
 * re-run these checks after locking the actor row.
 */
public final class AdminAuthorities {
    /** Administrates management roles only (first seat offline via AdminRoleCli). */
    public static final String SYSTEM_ADMIN = "ROLE_SYSTEM_ADMIN";
    /** Application/client lifecycle: register, view, update, enable/disable, secret rotation. */
    public static final String APP_ADMIN = "ROLE_APP_ADMIN";
    /** Read/export the console audit trail only. */
    public static final String AUDITOR = "ROLE_AUDITOR";
    /** Reserved for documented user operations; grants no console capability in this increment. */
    public static final String USER_OPERATOR = "ROLE_USER_OPERATOR";

    /** The role-writing surface of the console requires exactly SYSTEM_ADMIN. */
    public static final Set<String> ROLE_WRITE = Set.of(SYSTEM_ADMIN);
    /** Audit reads/exports: viewers must hold AUDITOR; SYSTEM_ADMIN retains oversight. */
    public static final Set<String> AUDIT_READ = Set.of(AUDITOR, SYSTEM_ADMIN);
    /** Client management: APP_ADMIN; SYSTEM_ADMIN retains the bootstrap/escalation seat. */
    public static final Set<String> CLIENT_MANAGE = Set.of(APP_ADMIN, SYSTEM_ADMIN);

    private AdminAuthorities() { }

    /** Live, non-inferred membership check: roles come from iam_user_role, never from the session. */
    public static boolean any(List<String> liveRoles, Set<String> required) {
        return liveRoles != null && liveRoles.stream().anyMatch(required::contains);
    }
}
