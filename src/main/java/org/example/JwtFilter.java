package org.example;

import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import io.jsonwebtoken.Claims;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * 3: Shiro Filter in Spring Boot
 * Here, we define the filter that will intercept requests and validate the JWT token.
 * 
 * @author tdiprima
 */
public class JwtFilter extends BasicHttpAuthenticationFilter {

    private JwtTokenUtil jwtTokenUtil = new JwtTokenUtil();

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String authHeader = httpRequest.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            String username = jwtTokenUtil.extractUsername(token);
            Claims claims = jwtTokenUtil.extractAllClaims(token);

            return jwtTokenUtil.validateToken(token, username);
        }

        return false;
    }
}
