package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.services.UserService;
import org.modelmapper.ModelMapper;
import com.substring.authapp.helpers.MessageHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Core implementation for user-related business logic and persistence.
 */
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final MessageHelper messageHelper;
    private final UserHelper userHelper;
    private final RoleRepository roleRepository;

    /**
     * Creates and persists a new ADMIN user who has special access with an encoded password.
     * This is used for internal organization-side user provisioning by a Root user.
     * 
     * @param userDto DTO containing the details for the new administrative account.
     * @return DTO of the newly created admin.
     */
    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        // 1. Validate business constraints (e.g., email uniqueness)
        userHelper.validateUserForSignup(userDto);

        // 2. Build and save the entity using the centralized organization/admin template
        return userHelper.buildAndSaveUser(userDto, Provider.ORGANIZATION, UserRole.ROLE_ADMIN);
    }

    /**
     * Retrieves a user by their email address.
     * Standardizes exception handling for consistent API error responses.
     */
    @Override
    public UserDto getUserByEmail(String email) {
        User user = userHelper.findUserByEmailOrThrow(
            email, 
            new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found"))
        );
        return modelMapper.map(user, UserDto.class);
    }

    /**
     * Updates an existing user's profile details.
     * Employs functional updates to only modify fields present in the request.
     * 
     * @param userDto DTO containing the fields to update.
     * @param userId  The unique ID of the user to be modified.
     * @return DTO of the updated user.
     */
    @Override
    @Transactional
    public UserDto updateUser(UserDto userDto, UUID userId) {
        User oldUser = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));
        
        // Use Optional.ofNullable to apply updates conditionally (Patch-like behavior)
        java.util.Optional.ofNullable(userDto.getProvider()).ifPresent(oldUser::setProvider);
        java.util.Optional.ofNullable(userDto.getName()).ifPresent(oldUser::setName);
        java.util.Optional.ofNullable(userDto.getImage()).ifPresent(oldUser::setImage);
        java.util.Optional.ofNullable(userDto.getPassword())
                .map(passwordEncoder::encode)
                .ifPresent(oldUser::setPassword);
        
        oldUser.setEnabled(userDto.isEnabled());
        
        User updatedUser = userRepository.save(oldUser);
        return modelMapper.map(updatedUser, UserDto.class);
    }

    /**
     * Performs a 'Silent Delete' (Soft Delete) of a user.
     * Instead of purging records, it disables the account to preserve data integrity and audit trails.
     */
    @Override
    @Transactional
    public void deleteUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));
        user.setEnabled(false);
    }

    /**
     * Retrieves a single user by their unique identifier.
     */
    @Override
    public UserDto getUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));
        return modelMapper.map(user, UserDto.class);
    }

    /**
     * Returns a list of all active registered users in the system.
     * Filters out disabled users to provide a 'clean' view of the current user base.
     */
    @Override
    public Iterable<UserDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .filter(User::isEnabled)
                .map(u -> modelMapper.map(u, UserDto.class))
                .toList();
    }


}
