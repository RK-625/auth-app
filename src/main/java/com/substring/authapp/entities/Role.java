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
 * 1. <b>Definition:</b> Static authorities stored in the {@code roles} table.
 * 2. <b>Association:</b> Linked to {@link User} via many-to-many relationship.
 * 3. <b>Handshake:</b> Managed by the <b>Persistence Context</b> during security principal hydration.
 * 4. <b>Enforcement:</b> Mapped to {@link org.springframework.security.core.GrantedAuthority}.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This entity is managed as a read-heavy component within the <b>Persistence Context</b>. 
 * Since roles are typically immutable after initialization, it does not implement 
 * <b>Optimistic Locking</b> via {@code @Version}. Structural integrity is maintained 
 * through strict <b>Database Constraints</b>.
 * </p>
 *
 * <p><b>Database Constraints & Persistence Logic:</b>
 * <ul>
 *   <li><b>Unique Authority:</b> The {@code role_name} column is marked as <b>Unique</b> and 
 *       <b>Non-nullable</b>, ensuring that no duplicate or orphan roles exist in the 
 *       <b>Persistence Context</b>.</li>
 *   <li><b>Stable Identifiers:</b> Uses {@link UUID} identifiers to prevent ID-guessing 
 *       attacks and ensure compatibility across different database vendors during 
 *       initialization (e.g., {@code data.sql}).</li>
 * </ul>
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Using a persistent entity for roles instead of simple strings allows for dynamic 
 * role management and complex relationship mapping, while the {@link UserRole} 
 * enum ensures type safety during development.
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

    // ===================================================================================
    // SECTION 1: Identity & Authority (Fields)
    // ===================================================================================

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
