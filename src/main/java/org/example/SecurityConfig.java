package org.example;

import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
//import org.pac4j.jwt.profile.JwtGenerator;
//import org.pac4j.jwt.client.JwtClient;

/**
 * Handles JWT authentication. Validate tokens from incoming requests.
 *
 * @author tdiprima
 */
public class SecurityConfig {

    // Example key for signing tokens
    private String secret = "mySuperSecretKey";

    public JwtAuthenticator jwtAuthenticator() {
        // Create the JwtAuthenticator
        JwtAuthenticator jwtAuthenticator = new JwtAuthenticator();
        jwtAuthenticator.addSignatureConfiguration(new SecretSignatureConfiguration(secret));

        // Create the JwtClient
//        JwtClient jwtClient = new JwtClient();
//        jwtClient.setAuthenticator(jwtAuthenticator);

        return jwtAuthenticator;
    }
}
