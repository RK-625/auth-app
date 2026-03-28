package com.substring.authapp.repositories;

import com.substring.authapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for {@link User} entity operations.
 * Provides abstraction for database access and custom query methods.
 */
public interface UserRepository extends JpaRepository<User, UUID> {
    
    /**
     * Retrieves a user based on their unique email address.
     * 
     * @param email The email to search for.
     * @return An {@link Optional} containing the user if found, or empty otherwise.
     */
    Optional<User> findByEmail(String email);

    /**
     * Checks if a user already exists with the given email.
     * 
     * @param email The email to check for existence.
     * @return true if a user exists with the email, false otherwise.
     */
    boolean existsByEmail(String email);

    /**
     * Deletes a user by their unique identifier.
     * 
     * @param id The UUID of the user to delete.
     */
    void deleteUserById(UUID id);
}
