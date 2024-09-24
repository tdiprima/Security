package org.example;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import java.util.Date;

/**
 * This utility can be used to check if the JWT has expired or is invalid.
 * 
 * @author tdiprima
 */
public class JwtUtil {

    private static final String SECRET_KEY = "mySuperSecretKey";

    public Claims parseToken(String jwtToken) {
        try {
            return Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .parseClaimsJws(jwtToken)
                    .getBody();
        } catch (SignatureException e) {
            // Handle invalid signature or token
            return null;
        }
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }
}
