package org.example;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * This utility can be used to check if the JWT has expired or is invalid.
 *
 * @author tdiprima
 */
public class JwtUtil {

    private static final String SECRET_KEY = "mySuperSecretKey";

    public Claims parseToken(String jwtToken) {
        try {
            Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)); // Key generation
            return Jwts.parserBuilder()
                       .setSigningKey(key)
                       .build()
                       .parseClaimsJws(jwtToken)
                       .getBody();
        } catch (SignatureException e) {
            // Handle invalid signature or token
            return null;
        }
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new java.util.Date());
    }
}
