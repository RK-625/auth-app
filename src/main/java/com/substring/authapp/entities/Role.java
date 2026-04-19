package com.substring.authapp.entities;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;
/**
 * <h1>Authorization Authority Entity</h1>
 *
 * <p>Represents an authorization Role within the system's RBAC (Role-Based Access Control) 
 * architecture. This entity maps security levels to persistent database records, 
 * providing the foundation for declarative security.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. Defined as a set of static authorities in the {@code roles} table.
 * 2. Associated with {@link User} entities through a many-to-many relationship.
 * 3. Loaded during authentication and mapped to {@link org.springframework.security.core.GrantedAuthority}.
 * 4. Used by {@code AccessDecisionVoter}s to permit or deny entry to secured resources.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This entity maps security levels to persistent database records. It uses a {@link UserRole} 
 * enum to ensure type safety and prevent the injection of arbitrary role names. The {@code role_name} 
 * column is indexed and unique to maintain integrity across the system.
 * </p>
 *
 * <p><b>Security Integrity:</b>
 * <ul>
 *   <li><b>{@code @Column(unique = true)}:</b> Enforces the uniqueness of role names at the schema 
 *       level, preventing redundant or conflicting authority definitions that could 
 *       weaken the RBAC model.</li>
 *   <li><b>{@link UserRole}:</b> A type-safe enumeration that acts as a compile-time 
 *       whitelist for all permissible system authorities.</li>
 * </ul>
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Roles are the building blocks of the system's authorization layer. They are mapped to 
 * {@link org.springframework.security.core.GrantedAuthority} during the authentication 
 * process, allowing for granular access control on API endpoints via annotations like 
 * {@code @PreAuthorize("hasRole('ADMIN')")}.
 * </p>
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "roles")
public class Role {
    /**
     * Unique identifier for the role.
     * Initialized with a random UUID to ensure uniqueness during manual 
     * data initialization (e.g., via {@code data.sql}).
     */
    @Id
    @Builder.Default
    private UUID id = UUID.randomUUID();

    /**
     * The type-safe name of the role (e.g., ROLE_USER, ROLE_ADMIN).
     * Mapped as a {@link String} in the database for readability while 
     * maintaining {@link UserRole} enum constraints in the Java layer.
     */
    @Enumerated(value = EnumType.STRING)
    @Column(name = "role_name", unique = true, nullable = false)
    private UserRole name;
}
