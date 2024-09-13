package org.example;

import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;

/**
 * Handles JWT authentication. Validate tokens from incoming requests.
 * 
 * @author tdiprima
 */
public class SecurityConfig {

    public JwtAuthenticator jwtAuthenticator() {
        JwtAuthenticator jwtAuthenticator = new JwtAuthenticator();
        jwtAuthenticator.addSignatureConfiguration(new SecretSignatureConfiguration("yourSecretKey"));
        return jwtAuthenticator;
    }
}
