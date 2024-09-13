package org.example;

import io.jsonwebtoken.Claims;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * A filter to intercept requests and check if the token is valid and hasn't expired.
 * If the token is expired, log the user out and redirect them to Keycloak for logout.
 *
 * @author tdiprima
 */
public class JwtTokenFilter extends AuthenticatingFilter {

    private JwtUtil jwtUtil = new JwtUtil();  // Utility to parse and validate JWT

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        // Extract JWT from Authorization header
        String jwtToken = getTokenFromRequest(request);
        if (jwtToken != null) {
            Claims claims = jwtUtil.parseToken(jwtToken);
            if (claims != null) {
                // Create an AuthenticationToken using parsed claims (e.g., username)
                String username = claims.getSubject();  // Assumes subject is the username
                return new UsernamePasswordToken(username, jwtToken);
            }
        }
        return null;  // If token is missing or invalid, return null
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        // Check for a valid token
        String token = getTokenFromRequest(request);
        if (token != null) {
            Claims claims = jwtUtil.parseToken(token);
            if (claims == null || jwtUtil.isTokenExpired(claims)) {
                // Token is invalid or expired, log out the user and redirect to Keycloak logout
                Subject subject = getSubject(request, response);
                if (subject != null) {
                    subject.logout();
                }
                redirectToKeycloakLogout(response);
                return false;
            }
            // Token is valid, proceed with authentication
            return executeLogin(request, response);
        }
        // If no token is present, deny access
        return false;
    }

    // @Override
    protected boolean onLoginFailure(AuthenticationToken token, Exception e, ServletRequest request, ServletResponse response) {
        // Handle login failure (e.g., invalid token)
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        try {
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return false;
    }

    private String getTokenFromRequest(ServletRequest request) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);  // Remove "Bearer " prefix
        }
        return null;
    }

    private void redirectToKeycloakLogout(ServletResponse response) throws Exception {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.sendRedirect("https://your-keycloak-server/auth/realms/{realm}/protocol/openid-connect/logout?redirect_uri=your-app-url");
    }
}
