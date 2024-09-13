### Summary of Real-World Setup

1. Keycloak handles the login and logout process, issuing JWTs.
2. Shiro manages session management, and pac4j integrates for JWT-based authentication.
3. io.jsonwebtoken is used to validate the token and check expiration.
4. Custom Filter intercepts every request, validates the JWT, and handles expiration by logging out and redirecting the user to Keycloak.
