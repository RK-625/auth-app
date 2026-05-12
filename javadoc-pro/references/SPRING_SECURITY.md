# Spring Security Deep Dive

This reference helps the agent identify the specific "magic" happening in a Spring Security flow.

## The Filter Chain
Spring Security is essentially a series of `Servlet Filters`.
- `SecurityContextPersistenceFilter`: Loads/Stores SecurityContext between requests.
- `LogoutFilter`: Monitors for logout requests.
- `UsernamePasswordAuthenticationFilter`: Handles traditional form login.
- `BasicAuthenticationFilter`: Handles Basic Auth headers.
- `FilterSecurityInterceptor`: Performs authorization (is the user allowed to access this URL?).

## Authentication Handshake
When `authenticationManager.authenticate()` is called:
1. `ProviderManager` (implementation of AuthenticationManager) iterates through `AuthenticationProviders`.
2. `DaoAuthenticationProvider` is usually the one that handles DB-based login.
3. It calls `UserDetailsService` to fetch the user.
4. It uses `PasswordEncoder` (e.g., `BCryptPasswordEncoder`) to verify the secret.

## JWT Mechanics
- **Claims**: The payload data (sub, iat, exp).
- **Signing**: HMAC or RSA signatures to prevent tampering.
- **Statelessness**: No session on the server; the token *is* the proof of identity.
- **Rotation**: Mitigates theft by issuing new refresh tokens on every use.
