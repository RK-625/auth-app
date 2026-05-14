# 🔐 Auth-App: Enterprise-Grade Identity API

A robust, "Clerk-like" Spring Boot authentication backend template. This repository provides a high-security, production-ready foundation for identity management, featuring a 3-phase registration handshake, hybrid JWT sessions, and JIT (Just-In-Time) OAuth2 provisioning.

---

## 🌟 Core Features (Current State)

### Security Architecture
*   **Dual-Token Hybrid Sessions:** Short-lived stateless Access Tokens (HS512) paired with long-lived, database-backed Refresh Tokens for precise revocation control.
*   **Two-Cookie Pattern:** Utilizes `HttpOnly` secure cookies for token storage alongside a public `logged_in` hint cookie to prevent XSS while allowing frontend state synchronization.
*   **3-Phase Handshakes:** Complex state machines for Signup and Password Reset, ensuring identity verification (OTP) occurs *before* sensitive data (passwords) is collected.
*   **Token Family Revocation (Kill-Switch):** Immediate invalidation of all user sessions if a compromised or previously revoked refresh token is presented.
*   **IP-Based Throttling:** Token-Bucket rate limiting at the filter level to block brute-force attacks before they hit the controller.

### Identity & Access
*   **JIT Social Provisioning:** Seamless GitHub and Google OAuth2 login that automatically provisions local user accounts and syncs profile metadata.
*   **Role-Based Access Control (RBAC):** Tiered authorities (`ROLE_USER`, `ROLE_ADMIN`, `ROLE_ROOT`).
*   **IDOR Protection:** Strict object-level authorization on profile updates.
*   **Soft Deletion:** Administrative account deactivation that preserves relational integrity.

### Engineering Standards
*   **100% Filter Isolation Coverage:** Custom `JwtAuthenticationFilter` and `RateLimitingFilter` are thoroughly tested.
*   **Optimistic Locking Mitigation:** Handles concurrent session renewals (HTTP 409) gracefully.
*   **Privacy-First Logging:** Uses a custom `PrivacyHelper` to redact PII (emails) from application logs.
*   **Container Ready:** Configured with Docker Compose (MySQL + Mailpit) for instant local development.

---

## 🛠️ Quick Start

### Prerequisites
*   Java 21+
*   Docker & Docker Compose (for local DB/Mail)
*   Maven

### Running Locally
1.  **Start Infrastructure:**
    ```bash
    docker-compose up -d
    ```
    *(This starts MySQL on port 3306 and Mailpit on port 8025)*

2.  **Configure Environment:**
    Copy the configuration template (if available) or rely on `application-dev.yml` defaults. Ensure you have valid OAuth2 Client IDs if testing social login.

3.  **Run the Application:**
    ```bash
    ./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
    ```

---

## 🗺️ Backend Implementation Roadmap (Pending Features)

This repository is continuously evolving to match the feature parity of commercial Identity-as-a-Service (IDaaS) platforms. The following critical backend features are prioritized for upcoming releases:

### High Priority (Critical Security & State Management)
*   [ ] **Expired Session Cleanup:** Implement a background cron job in `CleanupService` to purge expired `RefreshToken` rows to prevent database bloat.
*   [ ] **Session Management API:** Build endpoints (`GET /sessions`, `DELETE /sessions/{id}`) to allow users to view and revoke active logins across devices.
*   [ ] **Device Fingerprinting:** Capture and store `User-Agent` data within the `RefreshToken` entity to provide context in the Session Management UI.
*   [ ] **Email Enumeration Protection:** Standardize `/forget/email` and `/signup/request` to return uniform `200 OK` responses regardless of email existence, thwarting reconnaissance attacks.
*   [ ] **Soft-Delete Cascade Revocation:** Update `UserService.deleteUser()` to automatically revoke all active sessions when an account is deactivated.

### Medium Priority (User Experience & Hardening)
*   [ ] **Authenticated Password Change:** Add a `PUT /user/password` endpoint for logged-in users to update credentials without requiring the full OTP recovery flow.
*   [ ] **Self-Service Account Deletion:** Implement a GDPR-compliant `DELETE /user/me` endpoint.
*   [ ] **Brute-Force Account Lockout:** Introduce a `failedLoginAttempts` counter and temporary lockout threshold at the `User` entity level.

### Stretch Goals (Enterprise Scaling)
*   [ ] **Redis-Backed Rate Limiting:** Migrate the in-memory Bucket4j cache to Redis for global rate limiting across a multi-node deployment.
*   [ ] **Webhook Event System:** Publish HMAC-signed HTTP POST requests to configured URLs on events like `user.created` or `session.revoked`.
*   [ ] **Magic Link Login:** Implement passwordless email-link authentication.

---
*Built with Spring Boot 3 & Security.*