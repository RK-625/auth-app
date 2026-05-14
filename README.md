# 🔐 Auth-App: Enterprise-Grade Identity API

A robust, "Clerk-like" Spring Boot authentication backend template. This repository provides a high-security, production-ready foundation for identity management, featuring a 3-phase registration handshake, hybrid JWT sessions, and JIT (Just-In-Time) OAuth2 provisioning.

---

## 📖 Purpose & Vision
The `auth-app` is designed to provide developers with a **secure-by-default** identity infrastructure. It solves the complex "plumbing" of authentication (OTP state machines, token rotation, social JIT provisioning) so that engineering teams can focus on their core business logic without compromising on security or user experience.

---

## 🌟 Core Features

### Security Architecture
*   **Dual-Token Hybrid Sessions:** Combines the scalability of stateless Access Tokens (HS512) with the granular control of database-backed Refresh Tokens.
*   **Two-Cookie Pattern:** Implements the "Logged-In Hint" strategy using secure `HttpOnly` cookies to prevent XSS while maintaining a smooth frontend UX.
*   **3-Phase Handshakes:** Sophisticated state machines for **Signup** and **Password Reset** that ensure email ownership is verified via OTP before any sensitive data is collected or modified.
*   **Token Family Revocation (Kill-Switch):** Advanced security logic that detects token reuse (potential compromise) and immediately invalidates all active sessions for the affected user.
*   **Filter-Level Throttling:** Token-Bucket rate limiting implemented at the Servlet Filter level to protect against brute-force attacks at the absolute edge of the application.

### Identity & Access
*   **JIT Social Provisioning:** Integrated support for GitHub and Google OAuth2. Users are automatically provisioned in the local database upon successful social handshake, syncing profile metadata (names, avatars) on the fly.
*   **Multi-Tiered RBAC:** Out-of-the-box support for `ROLE_USER`, `ROLE_ADMIN`, and `ROLE_ROOT` hierarchies.
*   **IDOR Protection:** Built-in object-level authorization checks to prevent users from modifying profiles other than their own.
*   **Managed Soft Deletion:** Administrative endpoints for account deactivation that preserve relational database integrity for auditing.

### Engineering & DevOps
*   **Proactive Privacy:** Custom `PrivacyHelper` integration ensures that PII (like email addresses) is masked in system logs to comply with GDPR/Privacy standards.
*   **High-Fidelity Testing:** A comprehensive test suite using `@MockitoBean` and `MockMvc`, featuring 100% isolation coverage for all security filters and complex handshakes.
*   **Containerized Infrastructure:** One-click development setup via Docker Compose, orchestrating MySQL and Mailpit (SMTP testing tool).
*   **Observability:** Integrated Spring Actuator for health monitoring and custom security metrics (login success/failure counters).

---

## 🛠️ Quick Start

### Prerequisites
*   Java 21+
*   Docker & Docker Compose
*   Maven

### 1. Start Infrastructure
```bash
docker-compose up -d
```
*This will spin up a MySQL instance and a Mailpit SMTP server for local email testing.*

### 2. Configure Environment
Ensure your local `application-dev.yml` contains the necessary secrets (JWT secret, OAuth2 Client IDs). You can use environment variables or local property overrides.

### 3. Launch Application
```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

---
*Built with Spring Boot 3, Spring Security, and a focus on Architectural Integrity.*
