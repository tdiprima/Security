package org.example;

import io.jsonwebtoken.Claims;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

/**
 * A filter to intercept requests and check if the token is valid and hasn't expired. 
 * If the token is expired, log the user out and redirect them to Keycloak for logout.
 * 
 * @author tdiprima
 */
public class JwtTokenFilter extends AuthenticatingFilter {

    private JwtUtil jwtUtil = new JwtUtil();

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        String token = getTokenFromRequest(request);  // Extract JWT token from request
        if (token != null) {
            Claims claims = jwtUtil.parseToken(token);
            if (claims == null || jwtUtil.isTokenExpired(claims)) {
                // Token is expired or invalid, log out the user
                SecurityUtils.getSubject().logout();
                // Redirect to Keycloak logout
                ((HttpServletResponse) response).sendRedirect("https://keycloak-url/auth/realms/{realm}/protocol/openid-connect/logout?redirect_uri=your-app-url");
                return false; // Stop further processing
            }
            return true; // Token is valid, allow request
        }
        return false; // No token, deny access
    }

    private String getTokenFromRequest(ServletRequest request) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        return httpRequest.getHeader("Authorization"); // Extract JWT from Authorization header
    }
}

