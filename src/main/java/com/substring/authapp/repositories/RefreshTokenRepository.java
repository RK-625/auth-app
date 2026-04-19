package com.substring.authapp.repositories;

import com.substring.authapp.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Data Access Object (DAO) for managing {@link RefreshToken} persistence.
 *
 * <p><b>Behind the Scenes:</b>
 * At runtime, Spring Data JPA generates a proxy implementation of this interface using the 
 * {@code JpaRepositoryFactory}. This implementation encapsulates the {@code EntityManager} 
 * and handles transaction boundaries, boilerplate SQL generation, and result set mapping.
 * </p>
 *
 * <p><b>Query Generation Logic:</b>
 * Utilizes <b>Method Name Derivation</b>. The method {@code findByJti} is parsed by the 
 * {@code PartTree} logic to generate a {@code SELECT} query with a {@code WHERE jti = ?} 
 * clause, ensuring efficient indexed lookups.
 * </p>
 * 
 * @see RefreshToken For the entity structure and security purpose of JTI.
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /**
     * Retrieves a refresh token using its unique JWT ID handle.
     *
     * <p><b>Design Rationale:</b>
     * This lookup is critical for the "Refresh Token Rotation" and "Revocation" workflows.
     * By using the JTI instead of the primary key, we decouple the internal database ID 
     * from the public-facing token handle.
     * </p>
     * 
     * @param jti The unique "JWT ID" associated with the session.
     * @return An {@link Optional} containing the token record if valid and existing.
     */
    Optional<RefreshToken> findByJti(String jti);
}
