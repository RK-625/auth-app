# OAuth2 & JIT Provisioning

Reference for documenting Social Login and synchronization flows.

## JIT (Just-In-Time) Logic
- **Process**: The system intercepts the successful login via `OAuth2SuccessHandler`.
- **Sync**: It extracts attributes (email, name, avatar) from the provider (GitHub/Google).
- **Persistence**: If the user doesn't exist, it is created "on the fly." If it exists, specific attributes are synchronized.

## Security Mapping
- **Authorities**: External roles/groups must be mapped to local `UserRole` entities.
- **Passwordless**: These users have no password in the database (LOCAL provider only); authentication is delegated entirely to the external issuer.
