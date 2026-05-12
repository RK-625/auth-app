# Persistence & Transactions

Reference for explaining JPA and Hibernate mechanics.

## JPA Lifecycle
- **Transient**: New object, not in DB.
- **Managed/Persistent**: Object is tracked by the EntityManager. Changes will be synced to DB.
- **Detached**: No longer tracked (session closed).
- **Removed**: Scheduled for deletion.

## Database Index Optimization
- **Purpose**: Document `@Index` definitions to explain query performance.
- **Strategy**: Focus on unique indexes (like `jti`) for O(1) lookups during token verification.
- **Impact**: Explains why certain fields are marked `updatable = false` to preserve index integrity.

## @Transactional
- **Spring AOP**: Creates a proxy around the method.
- **Begin**: Transaction starts before method execution.
- **Commit**: Syncs changes to DB if method finishes successfully.
- **Rollback**: Reverts changes if a RuntimeException occurs.

## Data Transfer Objects (DTOs)
- **Why**: Decouples the API from the Database schema.
- **Security**: Prevents "Mass Assignment" vulnerabilities by exposing only specific fields.
- **Efficiency**: Reduces data transferred over the network.
