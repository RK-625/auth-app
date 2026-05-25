# Repository Guidelines

## Project Structure & Module Organization
This is a Spring Boot authentication service.

- Application code: `src/main/java/com/substring/authapp`
- Core packages:
  - `controllers/` (`AuthController`, `UserController`)
  - `services/` and `services/impl/` (business logic)
  - `security/` (JWT, OAuth2, filters, cookies)
  - `entities/` and `repositories/` (JPA domain + persistence)
  - `dtos/` (API request/response contracts)
  - `config/` (security, startup seeding, shared beans)
- Config/resources: `src/main/resources` (`application.yaml`, `application-dev.yml`, `messages.properties`)
- Tests: `src/test/java/com/substring/authapp` (unit, controller, security, integration)

## Build, Test, and Development Commands
- `./mvnw clean test`  
  Runs the full test suite.
- `./mvnw spring-boot:run -Dspring-boot.run.profiles=dev`  
  Starts the app locally with dev profile.
- `./mvnw clean package`  
  Builds the runnable JAR.
- `docker-compose up -d`  
  Starts local dependencies (MySQL, Mailpit).

Default local API port is `8083` in dev profile.

## Coding Style & Naming Conventions
- Java 21+ style, Spring Boot idioms, Lombok where already used.
- 4-space indentation; keep methods focused and transactional boundaries explicit.
- Class suffixes should match role: `*Controller`, `*Service`, `*Repository`, `*Request`, `*Response`.
- Prefer constructor injection (`@RequiredArgsConstructor`).
- Keep API-facing messages in `messages.properties` (no hardcoded user-facing strings).

## Testing Guidelines
- Frameworks: JUnit 5, Spring Boot Test, MockMvc, Mockito (`@MockitoBean`).
- Test classes should mirror target class names with `*Test` suffix (e.g., `AuthServiceImplTest`).
- Integration flows belong in `integration/` (example: `FullSignupHandshakeTest`).
- Run focused tests with: `./mvnw -Dtest=AuthControllerTest test`.

## Commit & Pull Request Guidelines
- Follow Conventional Commit style seen in history:  
  `feat: ...`, `fix: ...`, `refactor: ...`, `test: ...`, `docs: ...`, `chore: ...`, `security: ...`
- Keep subject lines imperative and scoped.
- PRs should include:
  - Problem and change summary
  - Testing evidence (commands/results)
  - Config/security impact (JWT, OAuth, cookies, rate limiting) if applicable
  - Linked issue(s)

## Security & Configuration Tips
- Never commit secrets. Use environment variables for DB, JWT, OAuth, and mail credentials.
- Validate all auth DTOs with `@Valid`.
- Preserve refresh-token cookie security flags and error response shape (`ApiError`) when modifying auth flows.
- **OAuth2 Token Security:** Never append JWT access tokens as query parameters during OAuth2 redirect callback. Rely on the double-cookie strategy (secure HttpOnly `refresh_token` and `logged_in` frontend hint) to transition credentials.

## Agent Maintenance Rule
- Treat this file as a living reference and update it proactively after meaningful changes.
- Update `AGENTS.md` in the same branch/PR whenever changes affect:
  - backend architecture or package boundaries
  - auth/session/OTP/OAuth/security flow behavior
  - API contracts (request/response DTOs, status codes, error shape)
  - configuration, infrastructure, or required dev commands
  - testing strategy or critical test coverage areas
- Keep updates concise, accurate, and formatted with clear headings and actionable bullets.
