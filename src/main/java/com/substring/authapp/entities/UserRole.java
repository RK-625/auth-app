package com.substring.authapp.entities;

/**
 * <h1>System Authority Definitions</h1>
 *
 * <p>Enumeration of available user roles within the application. These are used to control access to various endpoints and features.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Definition:</b> Explicitly defined roles form the basis of the RBAC model.
 * 2. <b>Mapping:</b> Assigned to {@link Role} entities which are in turn granted to {@link User} entities.
 * 3. <b>Enforcement:</b> Validated at runtime by Spring Security's method-level security (e.g., {@code @PreAuthorize("hasRole('ADMIN')")}).
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * These enums are transformed into {@link org.springframework.security.core.GrantedAuthority} collections during the authentication handshake, allowing the {@link org.springframework.security.access.intercept.FilterSecurityInterceptor} to evaluate access requests.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Using a strictly typed enum prevents typographical errors in role assignment and enforcement, ensuring that all access control rules are compiled and verified rather than relying on brittle strings.
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
