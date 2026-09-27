package com.substring.authapp.services;

import com.substring.authapp.dtos.admin.AdminUserCreateRequest;
import com.substring.authapp.dtos.admin.ManagementUserResponse;
import com.substring.authapp.dtos.user.AuthUserResponse;
import com.substring.authapp.dtos.user.PasswordChangeRequest;
import com.substring.authapp.dtos.user.UserUpdateRequest;
import com.substring.authapp.entities.User;
import java.util.UUID;

import org.springframework.validation.annotation.Validated;
import jakarta.validation.Valid;

/**
 * <h1>User Identity & Profile Management Contract</h1>
 * 
 * <p>Defines the administrative and self-service operations for managing the 
 * application's primary user identity pool. This interface abstracts the 
 * complexities of profile synchronization, administrative creation, and 
 * account deactivation.</p>
 * 
 * <p><b>Core Responsibilities:</b>
 * <ul>
 *   <li><b>Identity Provisioning:</b> Creating administrative users with specific roles.</li>
 *   <li><b>Profile Orchestration:</b> Managing non-sensitive user profile updates.</li>
 *   <li><b>Audit & Retrieval:</b> Providing fine-grained user discovery via ID or email.</li>
 *   <li><b>Access Control:</b> Enforcing soft-deletion and deactivation policies.</li>
 * </ul>
 * </p>
 * 
 * @author Gemini CLI
 */
@Validated
public interface UserService {

    // ===================================================================================
    // SECTION 1: Administrative Provisioning
    // ===================================================================================

    /**
     * Provisions a new administrative user with pre-defined privileges.
     * @param request DTO containing the admin user details.
     * @return A sanitized management view of the created user.
     */
    ManagementUserResponse createUser(@Valid AdminUserCreateRequest request);

    // ===================================================================================
    // SECTION 2: Profile Orchestration
    // ===================================================================================

    /**
     * Updates profile-level information (Name, Avatar) for an existing user.
     * @param request The update payload.
     * @param userId The unique ID of the user to modify.
     * @return A sanitized response for self-service consumption.
     */
    AuthUserResponse updateUser(@Valid UserUpdateRequest request, UUID userId);

    /**
     * Deactivates a user account (Soft-Delete) to terminate system access.
     * @param userId The unique ID of the account to deactivate.
     */
    void deleteUser(UUID userId);

    /**
     * Changes the password for an authenticated user.
     * @param request The password change payload.
     * @param currentUser The authenticated principal.
     */
    void changePassword(@Valid PasswordChangeRequest request, User currentUser);

    // ===================================================================================
    // SECTION 3: Identity Retrieval (Query)
    // ===================================================================================

    /**
     * Retrieves a sanitized user profile using their email address.
     * @param email The target email address.
     * @return A management response DTO.
     */
    ManagementUserResponse getUserByEmail(String email);

    /**
     * Locates a user by their persistent internal identifier.
     * @param userId The unique UUID.
     * @return A management response DTO.
     */
    ManagementUserResponse getUserById(UUID userId);

    /**
     * Retrieves a collection of all active users in the system.
     * @return An iterable of user management views.
     */
    Iterable<ManagementUserResponse> getAllUsers();
}
