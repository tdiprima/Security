## Summary of Real-World Setup

1. **Keycloak** handles the login and logout process, issuing JWTs.
2. **Shiro** manages session management, and
3. `pac4j` integrates for JWT-based authentication.
3. `io.jsonwebtoken` is used to validate the token and check expiration.
4. **Custom Filter** intercepts every request, validates the JWT, and handles expiration by logging out and redirecting the user to Keycloak.

# Details

## JWT Authentication Code Breakdown

Let's break down each part of this JWT authentication code to understand what it's doing and why:

### JwtTokenFilter
This class extends `AuthenticatingFilter`, which means it is responsible for intercepting requests and determining whether a user is authenticated.

1. **`createToken` method**:
   - This method extracts the JWT token from the `Authorization` header.
   - It uses `jwtUtil.parseToken(jwtToken)` to decode the JWT and get the claims (information encoded in the token).
   - If the token is valid, it creates a `UsernamePasswordToken` object. This object is a common way to represent an authentication attempt in frameworks like Shiro. In this case, the `username` and `jwtToken` act as both the username and password (because JWTs are self-contained credentials).

2. **`onAccessDenied` method**:
   - This is called when access is denied or the user is not authenticated.
   - It checks for the presence of a JWT token in the request.
   - If a token is found, it verifies whether the token is valid and unexpired.
   - If the token is expired, the user is logged out (`subject.logout()`), and a redirect to Keycloak's logout page is triggered.
   - If the token is valid, it calls `executeLogin()` to proceed with authentication based on the token.

3. **`onLoginFailure` method**:
   - This method handles what happens if authentication fails (e.g., invalid token).
   - It sends an HTTP 401 Unauthorized response with a message saying the token is invalid.

4. **`getTokenFromRequest` method**:
   - This extracts the token from the `Authorization` header, which typically looks like `Bearer <JWT token>`.
   - If the header starts with `"Bearer "`, it strips this prefix and returns the token.

5. **`redirectToKeycloakLogout` method**:
   - When the token is expired, it redirects the user to the Keycloak logout endpoint.

### JwtUtil
This is a utility class to handle JWT token parsing and validation.

1. **`parseToken` method**:
   - It uses the secret key to verify and parse the JWT.
   - If the token's signature is invalid or cannot be parsed, it returns `null`.
   - The `Claims` object extracted from the token contains information like the subject (username), expiration date, etc.

2. **`isTokenExpired` method**:
   - This checks if the token is expired by comparing the expiration date of the token with the current date.

### SecurityConfig
This is the configuration for JWT handling.

1. **`jwtAuthenticator` method**:
   - It creates a `JwtAuthenticator` instance that will handle token authentication using the secret key to validate the signature.
   - This is part of the broader security configuration of the application and ensures tokens are signed with a known key.

### Why are we doing this?
- **JWT as authentication**: The JWT is a self-contained token that includes the user's claims (e.g., username, roles, expiration) and is signed to ensure it's not tampered with. This eliminates the need for server-side sessions.
- **Token validation**: By parsing the token (`jwtUtil.parseToken()`), we confirm that the token is valid (i.e., it hasn't been tampered with) and belongs to the right user.
- **Expiration checks**: Expired tokens are no longer valid, so we check for expiration to ensure only legitimate tokens are used.
- **Security**: By using a secret key (`SECRET_KEY`), we make sure that only tokens signed by our application can be trusted.
- **Seamless logouts**: When tokens expire, users are logged out, and we redirect them to Keycloak for proper session termination.

This setup ensures secure, token-based authentication where JWT tokens serve as credentials for users without needing to maintain server-side sessions.

<br>
