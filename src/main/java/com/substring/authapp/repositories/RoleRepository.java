package com.substring.authapp.repositories;

import com.substring.authapp.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * <h1>Role Persistence Authorization Provider</h1>
 *
 * <p>Data Access Object (DAO) for managing {@link Role} entities. This repository 
 * serves as the source of truth for the application's RBAC (Role-Based Access Control) 
 * system, providing the necessary persistence logic to link users with their 
 * respective authorities.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Discovery:</b> Performs high-performance lookups of role definitions by name.
 * 2. <b>Association:</b> Provides managed entities to the {@link com.substring.authapp.helpers.UserHelper} 
 *    for linking with new or existing users.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * At runtime, Spring Data JPA generates a dynamic proxy implementation of this interface. 
 * It utilizes the {@code SimpleJpaRepository} base class to provide standard CRUD 
 * operations, while the {@code findByName} method is derived using <b>Method Name 
 * Parsing</b> to generate the appropriate JPQL query.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * By isolating role persistence, we ensure that the application's authorization 
 * structure is decoupled from the user management logic. This allows for the 
 * independent evolution of the role schema (e.g., adding permissions) without 
 * impacting the core user entity logic.
 * </p>
 * 
 * @author Gemini CLI
 * @see com.substring.authapp.entities.Role
 * @see com.substring.authapp.entities.UserRole
 */
public interface RoleRepository extends JpaRepository<Role, UUID> {
    
    /**
     * Finds a role by its unique name string.
     * 
     * <p><b>Implementation Workflow:</b>
     * Spring Data JPA parses the method name to generate a {@code SELECT r FROM Role r WHERE r.name = :name} 
     * query. This method is typically invoked during the registration flow or when 
     * promoting a user's privileges.
     * </p>
     *
     * @param name The name of the role (e.g., "ROLE_USER", "ROLE_ADMIN").
     * @return An {@link Optional} containing the role if it exists in the database.
     */
    Optional<Role> findByName(String name);
}
