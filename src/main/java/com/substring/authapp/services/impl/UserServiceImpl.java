package com.substring.authapp.services.impl;

import com.substring.authapp.dtos.admin.AdminUserCreateRequest;
import com.substring.authapp.dtos.admin.ManagementUserResponse;
import com.substring.authapp.dtos.user.AuthUserResponse;
import com.substring.authapp.dtos.user.UserUpdateRequest;
import com.substring.authapp.entities.Provider;
import com.substring.authapp.entities.Role;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.UserHelper;
import com.substring.authapp.repositories.RoleRepository;
import com.substring.authapp.repositories.RefreshTokenRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.services.UserService;
import com.substring.authapp.dtos.user.PasswordChangeRequest;
import org.modelmapper.ModelMapper;
import com.substring.authapp.helpers.MessageHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.BadCredentialsException;
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
 * <p><b>Behind the Scenes (Transactional Context):</b>
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
 * <p><b>Design Rationale (The "Why"):</b>
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

    // ===================================================================================
    // SECTION 1: Infrastructure & Dependencies (Fields)
    // ===================================================================================

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final MessageHelper messageHelper;
    private final UserHelper userHelper;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    // ===================================================================================
    // SECTION 2: Administrative User Creation
    // ===================================================================================

    /**
     * <h1>Administrative User Provisioning</h1>
     * 
     * <p>Creates a new administrative user with internal organization privileges.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates business constraints (e.g., email uniqueness) via {@link UserHelper}.
     * 2. Hashes the provided raw password using {@link PasswordEncoder}.
     * 3. Assigns the {@code ROLE_ADMIN} role and {@link Provider#ORGANIZATION} type.
     * 4. Persists the new user entity and returns the corresponding response view.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * This method is marked {@link Transactional}, ensuring that if the role assignment or 
     * persistence fails, the entire user creation is rolled back.</p>
     *
     * @param request DTO containing the details for the new administrative account.
     * @return ManagementUserResponse view of the newly created admin.
     */
    @Override
    @Transactional
    public ManagementUserResponse createUser(AdminUserCreateRequest request) {
        // 1. Validate business constraints (e.g., email uniqueness)
        userHelper.validateUserForSignup(request.getEmail(), request.getPassword());

        // 2. Build and save the entity using the centralized organization/admin template
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .provider(Provider.ORGANIZATION)
                .enabled(true)
                .build();

        // Assign ROLE_ADMIN
        Role adminRole = roleRepository.findByName(UserRole.ROLE_ADMIN)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("role.not_found")));
        user.setRoles(new HashSet<>(Set.of(adminRole)));

        User savedUser = userRepository.save(user);
        return modelMapper.map(savedUser, ManagementUserResponse.class);
    }

    // ===================================================================================
    // SECTION 3: Profile & Identity Management
    // ===================================================================================

    /**
     * <h1>Profile Update Orchestrator</h1>
     * 
     * <p>Updates an existing user's profile information using a partial-patch strategy.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Retrieves the current persistent entity from the database.
     * 2. Conditionally updates profile fields (name, image) if they are present in the request.
     * 3. Saves the updated entity and returns the new response view.
     * </p>
     *
     * <p><b>Behind the Scenes (JPA Managed State):</b>
     * Utilizes Hibernate's <b>Dirty Checking</b> mechanism. Changes made to a managed 
     * entity within a transaction are automatically synchronized during the flush phase, 
     * minimizing explicit UPDATE calls.</p>
     *
     * @param request DTO containing the profile fields to update.
     * @param userId  The unique ID of the user to be modified.
     * @return AuthUserResponse view of the updated user profile.
     */
    @Override
    @Transactional
    public AuthUserResponse updateUser(UserUpdateRequest request, UUID userId) {
        User oldUser = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));

        // Apply profile updates conditionally (Patch-like behavior)
        java.util.Optional.ofNullable(request.getName()).ifPresent(oldUser::setName);
        java.util.Optional.ofNullable(request.getImage()).ifPresent(oldUser::setImage);

        User updatedUser = userRepository.save(oldUser);
        return modelMapper.map(updatedUser, AuthUserResponse.class);
    }

    // ===================================================================================
    // SECTION 4: Account Termination & Deactivation
    // ===================================================================================

    /**
     * <h1>Soft-Delete Engine</h1>
     * 
     * <p>Deactivates a user account by toggling the enabled flag, preserving historical integrity.</p>
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Locates the persistent user entity by its unique UUID.
     * 2. Sets the {@code enabled} flag to {@code false} to prevent future logins.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * A "Soft Delete" strategy maintains referential integrity across related entities 
     * while effectively terminating system access.</p>
     *
     * @param userId The unique ID of the user to deactivate.
     */
    @Override
    @Transactional
    public void deleteUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));
        user.setEnabled(false);
        user.setTokenVersion(user.getTokenVersion() + 1);
        refreshTokenRepository.revokeAllByUser(user);
    }

    /**
     * <h1>Self-Service Password Change</h1>
     * 
     * <p>Allows an authenticated user to securely update their password.</p>
     */
    @Override
    @Transactional
    public void changePassword(PasswordChangeRequest request, User currentUser) {
        User user = userRepository.findById(currentUser.getId())
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadCredentialsException(messageHelper.getMessage("auth.login.invalid_credentials"));
        }

        userHelper.validateUserForSignup(user.getEmail(), request.getNewPassword());

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setTokenVersion(user.getTokenVersion() + 1);
        refreshTokenRepository.revokeAllByUser(user);
        userRepository.save(user);
    }

    // ===================================================================================
    // SECTION 5: Identity Lookup Utilities
    // ===================================================================================

    /**
     * <h1>Identity Resolver (Email)</h1>
     * 
     * <p>Retrieves a sanitized management view of a user by their email.</p>
     *
     * @param email The email address to look up.
     * @return ManagementUserResponse representing the found user.
     */
    @Override
    public ManagementUserResponse getUserByEmail(String email) {
        User user = userHelper.findUserByEmailOrThrow(
            email, 
            new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found"))
        );
        return modelMapper.map(user, ManagementUserResponse.class);
    }

    /**
     * <h1>Identity Resolver (UUID)</h1>
     * 
     * <p>Retrieves a sanitized management view of a user by their unique identifier.</p>
     *
     * @param userId The unique identifier.
     * @return ManagementUserResponse view mapped from the entity.
     */
    @Override
    public ManagementUserResponse getUserById(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("user.profile.not_found")));
        return modelMapper.map(user, ManagementUserResponse.class);
    }

    /**
     * <h1>Global Directory Provider</h1>
     * 
     * <p>Fetches all active (enabled) users in the system.</p>
     *
     * @return Iterable of ManagementUserResponse objects.
     */
    @Override
    public Iterable<ManagementUserResponse> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .filter(User::isEnabled)
                .map(u -> modelMapper.map(u, ManagementUserResponse.class))
                .toList();
    }
}
