package com.substring.authapp.repositories;

import com.substring.authapp.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepositry extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByJti(String jti);
}
