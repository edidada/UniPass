package com.unipass.server;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.time.*;

/** Redis session existence alone is insufficient after password change or directory lifecycle updates. */
final class SessionEpochFilter extends OncePerRequestFilter {
    private final AccountState accounts;
    private final Clock clock;
    private final LoginSessions sessions;
    SessionEpochFilter(AccountState accounts, Clock clock,LoginSessions sessions) { this.accounts = accounts; this.clock = clock;this.sessions=sessions; }
    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        // Recovery routes use their own browser-bound capability; never trust a stale principal here.
        return request.getServletPath().startsWith("/api/password/reset/") || request.getServletPath().equals("/api/public/csrf");
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof IdentityPrincipal principal) {
            boolean allowed;
            try { allowed = principal.getAuthenticatedAt().plus(Duration.ofDays(1)).isAfter(clock.instant()) && accounts.allowed(principal); }
            catch (RuntimeException e) { response.setStatus(503); return; }
            // Only the operation-status route keeps a recent, bounded recovery session during its own fence.
            boolean recoveryStatus;
            try { recoveryStatus = !allowed && request.getMethod().equals("GET") && request.getServletPath().matches("/api/password/operations/[a-fA-F0-9-]{36}")
                    && principal.hasRecentPassword(clock.instant())
                    && accounts.recoveryStatusAllowed(principal, request.getServletPath().substring(request.getServletPath().lastIndexOf('/') + 1)); }
            catch (RuntimeException e) { response.setStatus(503); return; }
            if (!allowed && !recoveryStatus) {
                if (request.getSession(false) != null) request.getSession(false).invalidate();
                SecurityContextHolder.clearContext(); response.setStatus(401); return;
            }
            if(allowed){
                try {sessions.seen(principal,request.getHeader("User-Agent"));}
                catch(RuntimeException e){response.setStatus(503);return;}
            }
        }
        chain.doFilter(request, response);
    }
}
