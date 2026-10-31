package com.test.examples.unipass.server;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A disabled application must not start new authorizations or authenticate at any protocol
 * endpoint, even while its Redis/JWT state is still being cleaned up. This filter runs before the
 * authorization-server filters so the decision does not depend on any provider ordering.
 */
final class ClientStatusFilter extends OncePerRequestFilter {
  private static final Set<String> GUARDED =
      Set.of("/oauth/authorize", "/oauth/token", "/oauth/introspect", "/oauth/revoke");
  private final JdbcTemplate jdbc;

  ClientStatusFilter(JdbcTemplate jdbc) {
    this.jdbc = jdbc;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !GUARDED.contains(request.getServletPath());
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    String clientId = clientId(request);
    if (clientId == null) {
      chain.doFilter(request, response);
      return;
    }
    Boolean disabled =
        jdbc.query(
            "SELECT disabled FROM oauth_client_status WHERE client_id=?",
            r -> r.next() ? r.getBoolean(1) : Boolean.FALSE,
            clientId);
    if (!Boolean.TRUE.equals(disabled)) {
      chain.doFilter(request, response);
      return;
    }
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setHeader("Cache-Control", "no-store");
    response.setContentType("application/json");
    response.getWriter().write("{\"error\":\"invalid_client\"}");
  }

  private String clientId(HttpServletRequest request) {
    String[] values = request.getParameterValues("client_id");
    if (values != null && values.length == 1 && values[0] != null && !values[0].isBlank())
      return values[0];
    String header = request.getHeader("Authorization");
    if (header == null || !header.regionMatches(true, 0, "Basic ", 0, 6)) return null;
    try {
      String decoded =
          new String(
              Base64.getDecoder().decode(header.substring(6).trim()), StandardCharsets.UTF_8);
      int separator = decoded.indexOf(':');
      return separator > 0 ? decoded.substring(0, separator) : null;
    } catch (IllegalArgumentException malformed) {
      return null; // the authorization-server provider rejects malformed headers
    }
  }
}
