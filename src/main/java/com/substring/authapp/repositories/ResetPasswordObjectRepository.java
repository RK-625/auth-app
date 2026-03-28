package com.substring.authapp.repositories;

import com.substring.authapp.entities.ResetPasswordObject;
import com.substring.authapp.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ResetPasswordObjectRepository extends JpaRepository<ResetPasswordObject, UUID> {

    boolean existsByUserAndOtpAndResetToken(User user, String Otp, UUID resetToken);

    Optional<ResetPasswordObject> findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual(User user, String Otp, Instant expiresAt);

    boolean existsByUserAndResetTokenAndExpiresAtGreaterThan(User user, UUID resetToken, Instant expiresAt);
}