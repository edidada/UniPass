package com.unipass.server;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

/** Strict contract before any authentication redirect, including loopback port and duplicate checks. */
final class AuthorizationRequestGuard extends OncePerRequestFilter {
    private final RegisteredClientRepository clients;
    private final AccountState accounts;
    AuthorizationRequestGuard(RegisteredClientRepository clients, AccountState accounts) { this.clients = clients; this.accounts = accounts; }
    @Override protected boolean shouldNotFilter(HttpServletRequest request) { return !request.getServletPath().equals("/oauth/authorize"); }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        boolean invalid = false;
        for (String key : List.of("response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "nonce")) {
            String[] values = request.getParameterValues(key); if (values != null && values.length != 1) invalid = true;
        }
        String clientId = request.getParameter("client_id"); var client = clientId == null ? null : clients.findByClientId(clientId);
        String challenge = request.getParameter("code_challenge"), state = request.getParameter("state");
        invalid |= client == null || !"code".equals(request.getParameter("response_type"))
                || !"S256".equals(request.getParameter("code_challenge_method")) || challenge == null || !challenge.matches("[A-Za-z0-9_-]{43}")
                || state == null || state.isBlank() || state.length() > 500
                || client != null && !client.getRedirectUris().contains(request.getParameter("redirect_uri"));
        if (invalid) {
            response.setStatus(400); response.setContentType("application/json"); response.getWriter().write("{\"error\":\"invalid_request\"}"); return;
        }
        var authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof IdentityPrincipal principal && accounts.mustChange(principal.getUserId())) {
            response.setStatus(403); response.setContentType("application/json"); response.getWriter().write("{\"error\":\"password_change_required\"}"); return;
        }
        chain.doFilter(request, response);
    }
}
