package com.substring.authapp.helpers;

import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import com.substring.authapp.helpers.MessageHelper;
import org.modelmapper.ModelMapper;
import org.springframework.data.util.Pair;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Helper component for user-related utility operations and validations.
 */
@Component
@RequiredArgsConstructor
public class UserHelper {

    private final MessageHelper messageHelper;
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    /**
     * Performs business validation on a UserDto before signup.
     * Checks for existing account conflicts.
     * 
     * @param userDto The DTO to validate.
     * @throws IllegalArgumentException if validation fails.
     */
    public void validateUserForSignup(UserDto userDto){
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.email_required"));
        }
        
        if (userDto.getPassword() == null || userDto.getPassword().length() < 6) {
             throw new IllegalArgumentException(messageHelper.getMessage("user.register.password_too_short"));
        }

        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.email_exists"));
        }
    }

    public UserDto buildAndSaveUser(UserDto userDto, Provider provider, UserRole roleName) {
        User user = modelMapper.map(userDto, User.class);
        user.setProvider(provider);
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));

        Set<Role> roles = new HashSet<>();
        Role defaultRole = roleRepository.findByName(roleName.name())
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("role.not_found")));
        roles.add(defaultRole);
        user.setRoles(roles);
        
        User savedUser = userRepository.save(user);
        UserDto dto = modelMapper.map(savedUser, UserDto.class);
        dto.setId(null);
        return dto;
    }

    public User findUserByEmailOrThrow(String email, RuntimeException notFoundException) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException(messageHelper.getMessage("user.register.email_required"));
        }
        return userRepository.findByEmail(email).orElseThrow(() -> notFoundException);
    }

    public static Pair<String,UUID> generateSecureOtpAndToken() {
         SecureRandom secureRandom = new SecureRandom();
         int otp = 100000 + secureRandom.nextInt(900000);
         UUID resetToken = UUID.randomUUID();
         return Pair.of(String.valueOf(otp), resetToken);
    }

}
