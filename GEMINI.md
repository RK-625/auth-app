# Project: auth-app

## 1. Project Overview
A high-performance, secure authentication and identity management service built on the modern Spring ecosystem. The application provides a robust foundation for user registration, multi-factor handshakes, and social identity integration, designed with a "security-first" and "fail-fast" philosophy.

- **Tech Stack:** Spring Boot 3.5.7, Java 25.
- **Persistence:** JPA/Hibernate with MySQL (production) and H2 (test).
- **Identity:** Custom identity provider with OAuth2 (GitHub) integration.

## 2. Architectural Patterns

### Hybrid Session Model
The system employs a **Stateful Stateless** architecture:
- **Access Tokens:** Short-lived HS512 JWTs carrying full identity claims (roles, email) to enable zero-database authorization checks.
- **Refresh Tokens:** Long-lived, stateful tokens stored in the database. This allows for a "Global Kill-Switch" to revoke sessions instantly while maintaining the scalability of JWTs.

### Three-Phase Handshake
Registration and password recovery utilize a structured handshake process:
1. **Initiate:** User requests an action (sign-up/reset).
2. **Verify:** Validation of ownership via out-of-band communication (Email OTP).
3. **Complete:** Final persistence of the new state.

### Provisioning Strategies
- **JIT Provisioning:** OAuth2 users (GitHub) are provisioned "Just-In-Time" upon successful first-time social login via `OAuth2SuccessHandler`.
- **Deferred Provisioning:** Uses staging tables (`SignUpObject`, `ResetPasswordObject`) to hold transient state during handshakes, ensuring the primary `User` table remains free of unverified or "half-created" accounts.

## 3. Security & Safety

### Cryptography & JWT
- **Algorithm:** HMAC SHA-512 (HS512) for all token signing.
- **Dual-Token Profiles:** Access tokens are claim-heavy; Refresh tokens are claim-light (JTI-only) to minimize exposure if intercepted.

### Rate Limiting (DDoS Protection)
- **Engine:** Bucket4j.
- **Strategy:** IP-based token bucket algorithm.
- **Placement:** The `RateLimitingFilter` is the absolute front-line, short-circuiting abusive traffic before it hits expensive JWT parsing or database logic.

### Filter Orchestration
Security is enforced via an ordered chain in `SecurityConfig`:
`RateLimitingFilter` -> `JwtAuthenticationFilter` -> `UsernamePasswordAuthenticationFilter`.

## 4. Observability & Monitoring

### Tiered Exposure Model
To balance visibility with security, the application employs a tiered Actuator model:
- **Public Layer:** `/actuator/health` is permitted for all traffic to support Liveness/Readiness probes by load balancers.
- **Admin Layer:** All other endpoints (`/metrics`, `/prometheus`, `/env`) require `ROLE_ADMIN` and a valid JWT.

### Custom Health Monitoring
The system uses the `CleanupServiceHealthIndicator` to track the health of background maintenance tasks. This ensures that the "Hourly Garbage Collection" of stale tokens is functioning correctly.

### Security Metrics (Counters)
Real-time tracking is implemented via Micrometer for the following critical events:
- `auth.rate.limit.blocked`: Tracked in `RateLimitingFilter`.
- `auth.login.success`: Tracked in `AuthServiceImpl`.
- `auth.login.failure`: Tracked in `AuthController`.

## 5. Security Hardening & Concurrency

### Token Rotation Safety (Optimistic Locking)
The system prevents race conditions during concurrent refresh token rotation using **JPA Optimistic Locking**.
- **Mechanism:** The `RefreshToken` entity includes a `@Version` field.
- **Outcome:** If two requests attempt to rotate the same token simultaneously, the second request fails with an `ObjectOptimisticLockingFailureException` (mapped to HTTP 409 Conflict), preventing duplicate session issuance.

### Token Theft Prevention (Family Revocation)
To mitigate "Token Reuse" attacks, the system implements the **Kill-Switch** pattern:
- **Detection:** If a token that has already been marked as `revoked` is presented during the refresh flow, the system assumes a compromise.
- **Action:** The `AuthServiceImpl` triggers a **Token Family Revocation**, immediately invalidating *all* active refresh tokens for that user.
- **Outcome:** The legitimate user and the attacker are both forced to re-authenticate via password, flushing all compromised sessions from the system.

## 6. Development Conventions

### Testing Standards (Spring Boot 3.4+)
- **Mocking:** All tests must use `@MockitoBean` instead of the deprecated `@MockBean`.
- **Validation:** Integration tests must verify both API responses and subsequent database state transitions.

### Validation & "Fail-Fast"
- **Layer:** Strictly enforced at the DTO layer using JSR-303 annotations.
- **Outcome:** Invalid requests are rejected at the controller boundary before reaching service logic.

### Unified Error Handling
- **GlobalExceptionHandler:** Centralized mapping of all exceptions to a standard `ApiError` schema.
- **Uniformity:** All error responses return consistent HTTP status codes and localized messages via `MessageHelper`.

### Package Organization
- `config`: Infrastructure and security orchestration.
- `dtos`: "Fail-Fast" data transfer objects.
- `entities`: JPA models (User, Role, RefreshToken, Staging Objects).
- `security`: JWT logic, filters, and OAuth2 handlers.
- `services`: Business logic and handshake management.

## 7. Maintenance & Garbage Collection

### CleanupService
An automated, hourly Scheduled task responsible for "Garbage Collection" of stale security artifacts:
- Purges expired `RefreshToken` records.
- Cleans up abandoned `SignUpObject` and `ResetPasswordObject` handshake state.
- Ensures the database does not accumulate transient "handshake noise."

## 8. Key File Index

| Component | Path |
| :--- | :--- |
| **Security Hub** | `src/main/java/com/substring/authapp/config/SecurityConfig.java` |
| **JWT Engine** | `src/main/java/com/substring/authapp/security/JwtService.java` |
| **Auth Logic** | `src/main/java/com/substring/authapp/services/impl/AuthServiceImpl.java` |
| **Rate Limiter** | `src/main/java/com/substring/authapp/security/RateLimitingFilter.java` |
| **GC Logic** | `src/main/java/com/substring/authapp/services/CleanupService.java` |
| **Error Schema** | `src/main/java/com/substring/authapp/dtos/common/ApiError.java` |
| **OAuth2 Entry** | `src/main/java/com/substring/authapp/security/OAuth2SuccessHandler.java` |
