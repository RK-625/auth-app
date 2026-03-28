package com.substring.authapp.helpers;

import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Helper component for user-related utility operations and validations.
 */
@Component
@RequiredArgsConstructor
public class UserHelper {

    private final MessageSource messageSource;
    private final UserRepository userRepository;

    /**
     * Safely parses a UUID from a string.
     */
    public static UUID parseUUID(String id){
        try {
            return UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid UUID format: " + id);
        }
    }

    /**
     * Performs business validation on a UserDto before signup.
     * Checks for missing email and existing account conflicts.
     * 
     * @param userDto The DTO to validate.
     * @throws IllegalArgumentException if validation fails.
     */
    public void validateUserForSignup(UserDto userDto){
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException(msg("user.register.email_required"));
        }
        
        if (userDto.getPassword() == null || userDto.getPassword().length() < 8) {
             throw new IllegalArgumentException(msg("user.register.password_too_short"));
        }

        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException(msg("user.register.email_exists"));
        }
    }

    public static Pair<String,UUID> generateSecureOtpAndToken() {
         SecureRandom secureRandom = new SecureRandom();
         int otp = 100000 + secureRandom.nextInt(900000);
         UUID resetToken = UUID.randomUUID();
         return Pair.of(String.valueOf(otp), resetToken);
    }
    private String msg(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }
}
