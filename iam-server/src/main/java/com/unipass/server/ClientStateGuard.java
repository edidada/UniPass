package com.unipass.server;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

/**
 * Live enable/disable fence for the T8 application lifecycle. Every
 * non-browser issuance path (public client refresh, authorization save) takes
 * the client row lock and re-reads the durable enabled column, so disabled
 * clients can never mint, exchange or refresh credentials and disable/update
 * serializes against in-flight issuance without stale-cache fail-open.
 */
final class ClientStateGuard {
    private final JdbcTemplate jdbc;
    ClientStateGuard(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    /** Locks the registration row and rejects a disabled or unknown client. */
    void requireEnabledRowLock(String clientId) {
        Boolean enabled = jdbc.query("SELECT enabled FROM oauth2_registered_client WHERE client_id=? FOR UPDATE",
                rs -> rs.next() ? rs.getBoolean(1) : null, clientId);
        if (enabled == null || !enabled)
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                    "Client authentication failed: state", null));
    }
}
