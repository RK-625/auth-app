package com.substring.authapp.repositories;

import com.substring.authapp.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for {@link Role} entity operations.
 */
public interface RoleRepository extends JpaRepository<Role, UUID> {
    
    /**
     * Finds a role by its name.
     * 
     * @param name The name of the role (e.g., "ROLE_USER").
     * @return An {@link Optional} containing the role if found.
     */
    Optional<Role> findByName(String name);
}
