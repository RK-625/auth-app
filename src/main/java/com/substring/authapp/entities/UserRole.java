package com.substring.authapp.entities;

/**
 * <h1>System Authority Definitions</h1>
 *
 * <p>Enumeration of available user roles within the application's RBAC model. 
 * These define the granular permissions assigned to persistent identities.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Definition:</b> Explicitly defined roles form the basis of the RBAC model.
 * 2. <b>Mapping:</b> Assigned to {@link Role} entities which are managed within the <b>Persistence Context</b>.
 * 3. <b>Enforcement:</b> Validated at runtime by Spring Security's method-level security filters.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * These enums are transformed into {@link org.springframework.security.core.GrantedAuthority} 
 * collections during the authentication handshake. They are stored as 
 * <b>Unique Constraints</b> in the {@code roles} table, ensuring that the 
 * <b>Persistence Context</b> maintains a 1:1 mapping between the enum and 
 * its database record.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Using a strictly typed enum prevents typographical errors and ensures 
 * <b>Type Safety</b> during security enforcement. It facilitates a clean 
 * <b>Decoupling</b> between the business logic and the underlying 
 * string-based authority checks in Spring Security.
 * </p>
 */
public enum UserRole {
    /** Regular user with standard access permissions. */
    ROLE_USER, 

    /** Administrator with elevated access permissions. */
    ROLE_ADMIN, 

    /** Root user with full system access. */
    ROLE_ROOT;
}
