package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.RefreshToken;
import com.substring.authapp.entities.ResetPasswordObject;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.RefreshTokenRepository;
import com.substring.authapp.repositories.ResetPasswordObjectRepository;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.AuthService;
import com.substring.authapp.services.EmailService;
import com.substring.authapp.services.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import com.substring.authapp.helpers.MessageHelper;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Service to handle registration and authentication related operations.
 */
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final UserHelper userHelper;
    private final MessageHelper messageHelper;
    private final RoleRepository roleRepository;
    
    private final ResetPasswordObjectRepository resetPasswordObjectRepository;
    private final EmailService emailService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    /**
     * Registers a new user account, ensuring the password is encrypted and default roles are assigned.
     * This method handles manual web signups (LOCAL provider).
     * 
     * @param userDto DTO containing user signup details.
     * @return DTO of the persisted user with sensitive fields removed.
     */
    @Override
    public UserDto signupUser(UserDto userDto) {
        userHelper.validateUserForSignup(userDto);
        return userHelper.buildAndSaveUser(userDto, Provider.LOCAL, UserRole.ROLE_USER);
    }

    /**
     * Triggers the password reset flow by generating a secure OTP and reset token.
     * If an active OTP already exists, it resends the existing one to avoid flood.
     */
    @Override
    @Transactional
    public void initiatePasswordReset(String email) {
        // 1. Verify user existence
        User user = validateEmailAndGetUser(email);
        
        // 2. Check if a valid, unexpired OTP already exists in the database
        Optional<ResetPasswordObject> activeOtp = resetPasswordObjectRepository.findByUserAndExpiresAtGreaterThan(user, Instant.now());
        
        if (activeOtp.isPresent()) {
            // Rate limiting/Spam prevention: reuse the active OTP
            emailService.sendPassWordResetOtp(user.getEmail(), activeOtp.get().getOtp());
        } else {
            // 3. Clear any old, stale reset requests for this user
            resetPasswordObjectRepository.deleteAllByUser(user);
            
            // 4. Generate new cryptographically secure credentials
            var keys = UserHelper.generateSecureOtpAndToken();
            while (resetPasswordObjectRepository.existsByUserAndOtpAndResetToken(user, keys.getFirst(), keys.getSecond())) {
                keys = UserHelper.generateSecureOtpAndToken();
            }
            
            ResetPasswordObject resetPasswordObject = new ResetPasswordObject(user, keys.getFirst(), keys.getSecond());
            resetPasswordObjectRepository.save(resetPasswordObject);
            
            // 5. Dispatch the OTP via the email provider
            emailService.sendPassWordResetOtp(user.getEmail(), keys.getFirst());
        }
    }

    /**
     * Verifies the OTP provided by the user. If valid, marks it as 'used' 
     * but extends its validity slightly to allow the final reset step.
     */
    @Override
    @Transactional
    public String verifyPasswordResetOtp(String email, String otp) {
        User user = validateEmailAndGetUser(email);
        
        ResetPasswordObject resetPasswordObject = resetPasswordObjectRepository
                .findByUserAndOtpAndUsedFalseAndExpiresAtGreaterThanEqual(user, otp, Instant.now())
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("auth.forget.otp_invalid")));
        
        // Mark OTP as verified/used
        resetPasswordObject.setUsed(true);
        // Provide a 60-second grace period for the client to submit the new password
        resetPasswordObject.setExpiresAt(Instant.now().plusSeconds(60));
        resetPasswordObjectRepository.save(resetPasswordObject);
        
        return resetPasswordObject.getResetToken().toString();
    }

    /**
     * Final step of the password reset flow. Updates the user's password in the database
     * after verifying the OTP and the secure reset token.
     */
    @Override
    @Transactional
    public void resetPassword(String email, String otp, String resetToken, String newPassword) {
        User user = validateEmailAndGetUser(email);
        
        // Final security check: verify that this specific OTP/Token combo was verified and hasn't expired
        boolean valid = resetPasswordObjectRepository
                .findByUserAndExpiresAtGreaterThanAndUsedTrueAndOtpAndResetToken(user, Instant.now(), otp, UUID.fromString(resetToken))
                .isPresent();
        
        if (valid) {
            // Update the password using the standard secure encoder
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            
            // Clean up: delete the reset object immediately after use
            resetPasswordObjectRepository.deleteAllByUser(user);
        } else {
            throw new BadCredentialsException(messageHelper.getMessage("auth.forget.otp_invalid"));
        }
    }

    /**
     * Creates and persists a new refresh token entry in the database.
     * This provides a server-side audit trail and allows for session revocation.
     */
    @Override
    public RefreshToken createRefreshToken(User user) {
        String refreshTokenJti = UUID.randomUUID().toString();
        return refreshTokenRepository.save(RefreshToken.create(user, refreshTokenJti, jwtService.getRefreshTtlSeconds()));
    }

    /**
     * Implements 'Refresh Token Rotation'.
     * Revokes the old token and issues a completely new one to detect/prevent replay attacks.
     */
    @Override
    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {
        // 1. Invalidate the old token permanently
        oldToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        oldToken.setReplacedByToken(newJti);
        refreshTokenRepository.save(oldToken);
        
        // 2. Provision and return a fresh token
        return refreshTokenRepository.save(RefreshToken.create(oldToken.getUser(), newJti, jwtService.getRefreshTtlSeconds()));
    }

    /**
     * Performs multi-layered validation on a refresh token string.
     * Checks signature, expiration, database presence, and revocation status.
     */
    @Override
    public RefreshToken getValidatedRefreshToken(String refreshTokenStr) {
        // Parse once to extract claims (Performance optimization)
        io.jsonwebtoken.Claims claims = jwtService.parse(refreshTokenStr).getPayload();
        String jti = claims.getId();
        UUID userId = UUID.fromString(claims.getSubject());
        
        // 1. Verify existence in the revocation database
        RefreshToken refreshTokenOb = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("token.refresh.not_found_db")));
                
        // 2. Critical security checks
        if (refreshTokenOb.isRevoked()) throw new BadCredentialsException(messageHelper.getMessage("token.refresh.revoked"));
        if (refreshTokenOb.getExpiresAt().isBefore(Instant.now())) throw new BadCredentialsException(messageHelper.getMessage("token.refresh.expired"));
        
        // 3. Ownership check: ensure the token belongs to the user specified in the JWT payload
        if (!refreshTokenOb.getUser().getId().equals(userId)) throw new BadCredentialsException(messageHelper.getMessage("token.refresh.user_mismatch"));
        
        return refreshTokenOb;
    }

    /**
     * Internal helper to retrieve a user entity while standardizing error messaging.
     */
    private User validateEmailAndGetUser(String email) {
        return userHelper.findUserByEmailOrThrow(
            email, 
            new BadCredentialsException(messageHelper.getMessage("auth.forget.email_not_found"))
        );
    }


}