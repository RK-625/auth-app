package com.substring.authapp.repositories;

import com.substring.authapp.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for {@link RefreshToken} entity operations.
 * Refresh tokens are used to obtain new access tokens after they expire.
 */
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /**
     * Finds a refresh token by its unique JWT ID (jti).
     * 
     * @param jti The unique ID of the token.
     * @return An {@link Optional} containing the refresh token if found.
     */
    Optional<RefreshToken> findByJti(String jti);
}
