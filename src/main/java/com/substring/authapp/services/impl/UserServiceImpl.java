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
 * <h1>User Lifecycle Management Provider</h1>
 *
 * <p>Implements the core administrative and profile management logic for users. 
 * This service coordinates between the persistence layer, security utilities, and 
 * data transformation components.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Identity Management:</b> Orchestrates the creation and updates of user profiles.
 * 2. <b>Administrative Control:</b> Provides soft-delete and retrieval capabilities.
 * 3. <b>Security Integration:</b> Ensures that profile changes adhere to security standards (like password hashing).
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This service leverages several architectural patterns:
 * <ul>
 *   <li><b>Spring AOP Proxy:</b> The {@link Transactional} annotation triggers the creation 
 *       of a proxy around the method to manage database transaction boundaries.</li>
 *   <li><b>DTO Pattern:</b> Decouples the internal JPA {@link User} entity from the 
 *       external API contract using {@link ModelMapper}.</li>
 *   <li><b>JPA Dirty Checking:</b> Within transaction boundaries, modifications to 
 *       <b>Managed</b> entities are automatically synchronized with the database 
 *       upon commit via the {@code EntityManager} flush mechanism.</li>
 * </ul>
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Centralizes user-specific operations to ensure consistent application of 
 * security rules (like password hashing) and business constraints (like email 
 * uniqueness). By delegating assembly to the {@link UserHelper}, the service 
 * remains lightweight and focused on business orchestration.
 * </p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.services.UserService
 * @see com.substring.authapp.helpers.UserHelper
 * @see com.substring.authapp.repositories.UserRepository
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
     * Creates a new administrative user.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates business constraints (e.g., email uniqueness) via {@link UserHelper}.
     * 2. Hashes the provided raw password using {@link PasswordEncoder}.
     * 3. Assigns the {@code ROLE_ADMIN} role and {@link Provider#ORGANIZATION} type.
     * 4. Persists the new user entity and returns the corresponding DTO.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * This method is marked {@link Transactional}, ensuring that if the role assignment or 
     * persistence fails, the entire user creation is rolled back. The persistence 
     * context tracks the entity's transition from <b>Transient</b> to <b>Managed</b>.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Using a centralized assembly bridge ({@link UserHelper}) ensures that security 
     * defaults (like provider type and initial roles) are applied consistently 
     * across different user creation flows (Admin vs. Public).
     * </p>
     *
     * @param userDto DTO containing the details for the new administrative account.
     * @return DTO of the newly created admin.
     */
    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        // 1. Validate business constraints (e.g., email uniqueness)
        userHelper.validateUserForSignup(userDto.getEmail(), userDto.getPassword());

        // 2. Build and save the entity using the centralized organization/admin template
        return userHelper.buildAndSaveUser(userDto, Provider.ORGANIZATION, UserRole.ROLE_ADMIN);
    }

    /**
     * Retrieves a user profile by their email address.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Searches the database for a user matching the provided email via {@link UserRepository}.
     * 2. Throws a {@link ResourceNotFoundException} if the user is absent.
     * 3. Maps the entity to a {@link UserDto} for the return value.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Email lookups are the primary identification mechanism. Returning a DTO instead 
     * of the entity ensures that internal database fields (like version or 
     * salt) are not exposed to the calling layer.
     * </p>
     *
     * @param email The email address to look up.
     * @return UserDto representing the found user.
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
     * Updates an existing user's profile information.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Retrieves the current persistent entity from the database.
     * 2. Conditionally updates profile fields (name, image, provider) if they are present in the DTO.
     * 3. Saves the updated entity and returns the new DTO state.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * Utilizes JPA's <b>Managed State</b> mechanics. Once the entity is loaded within a 
     * transactional method, Hibernate tracks changes to it. This "Dirty Checking" 
     * minimizes database writes by only updating changed columns during the flush phase.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * This method is restricted to non-sensitive profile updates. Fields like 
     * {@code password} and {@code enabled} are purposefully excluded to ensure that 
     * account status and security credentials require dedicated, high-verification 
     * flows (e.g., password reset handshake or administrative override).
     * </p>
     *
     * @param userDto DTO containing the profile fields to update.
     * @param userId  The unique ID of the user to be modified.
     * @return DTO of the updated user profile.
     */
    @Override
    @Transactional
    public UserDto updateUser(UserDto userDto, UUID userId) {
        User oldUser = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));
        
        // Apply profile updates conditionally (Patch-like behavior)
        java.util.Optional.ofNullable(userDto.getProvider()).ifPresent(oldUser::setProvider);
        java.util.Optional.ofNullable(userDto.getName()).ifPresent(oldUser::setName);
        java.util.Optional.ofNullable(userDto.getImage()).ifPresent(oldUser::setImage);
        
        User updatedUser = userRepository.save(oldUser);
        return modelMapper.map(updatedUser, UserDto.class);
    }

    /**
     * Deactivates a user account (Soft Delete).
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Locates the persistent user entity by its unique UUID.
     * 2. Sets the {@code enabled} flag to {@code false} to prevent future logins.
     * </p>
     *
     * <p><b>Behind the Scenes (JPA Dirty Checking):</b>
     * This method relies on the **Managed State** of the entity. Because the method is marked 
     * {@link Transactional}, Hibernate tracks any changes made to the user object 
     * after it is fetched. Upon method completion, the transaction is committed, 
     * and Hibernate automatically synchronizes the state with the database via an 
     * {@code UPDATE} statement. An explicit call to {@code userRepository.save()} 
     * is therefore redundant but would achieve the same result.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * A "Soft Delete" strategy is employed to maintain referential integrity across the 
     * system. This ensures that historical data associated with the user remains 
     * intact while effectively terminating their access to the system.
     * </p>
     *
     * @param userId The unique ID of the user to deactivate.
     */
    @Override
    @Transactional
    public void deleteUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));
        user.setEnabled(false);
    }

    /**
     * Retrieves a user by their unique identifier.
     *
     * @param userId The unique identifier.
     * @return UserDto mapped from the entity.
     * @throws ResourceNotFoundException if the ID does not exist.
     */
    @Override
    public UserDto getUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));
        return modelMapper.map(user, UserDto.class);
    }

    /**
     * Fetches all active users in the system.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Retrieves all users from the {@link UserRepository}.
     * 2. Filters the list to include only those where {@code enabled == true}.
     * 3. Maps the resulting entities to DTOs.
     * </p>
     *
     * @return Iterable of UserDto objects.
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
