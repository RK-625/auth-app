package com.substring.authapp.entities;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;
/**
 * Entity representing a security role in the system.
 * Roles are used for authorization and access control (RBAC).
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
     */
    @Id
    @Builder.Default
    private UUID id = UUID.randomUUID();

    /**
     * The name of the role (e.g., ROLE_USER, ROLE_ADMIN).
     * Mapped from the {@link UserRole} enumeration.
     */
    @Enumerated(value = EnumType.STRING)
    @Column(name = "role_name", unique = true, nullable = false)
    private UserRole name;
}
