package com.substring.authapp.controllers;

import com.substring.authapp.dtos.admin.AdminUserCreateRequest;
import com.substring.authapp.dtos.admin.ManagementUserResponse;
import com.substring.authapp.dtos.user.AuthUserResponse;
import com.substring.authapp.dtos.user.PasswordChangeRequest;
import com.substring.authapp.dtos.user.UserUpdateRequest;
import com.substring.authapp.entities.User;
import com.substring.authapp.entities.UserRole;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.services.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * <h1>User Management Controller</h1>
 *
 * <p>Provides administrative and self-service endpoints for managing user profiles, 
 * roles, and account lifecycles. It acts as the orchestration layer between the 
 * RESTful API and the {@link UserService}.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. Exposes administrative endpoints for CRUD operations on user identities.
 * 2. Enforces payload validation using {@code @Valid} to ensure data integrity.
 * 3. Delegates complex business logic (role mapping, password hashing) to {@link UserService}.
 * 4. Transforms internal entities into {@link ManagementUserResponse} objects for secure external transmission.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This controller leverages Spring's {@code DispatcherServlet} for request routing 
 * and {@code RequestMappingHandlerMapping} to map URLs to specific methods. 
 * Dependency injection is handled via constructor injection, facilitated by Lombok's 
 * {@link RequiredArgsConstructor}, ensuring that the {@link UserService} is 
 * immutable and reliably provided at runtime.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Centralizes user-related operations while enforcing strict validation rules 
 * via JSR-303 annotations. This controller strictly adheres to <b>Semantic Status Codes</b>:
 * <ul>
 *   <li><b>201 Created:</b> Used for successful user creation via {@code createUser}.</li>
 *   <li><b>204 No Content:</b> Used for successful deletions to indicate a void but successful result.</li>
 *   <li><b>200 OK:</b> Used for retrieval and updates where data is returned.</li>
 * </ul>
 * </p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.services.UserService
 * @see ManagementUserResponse
 * @see com.substring.authapp.dtos.user.UserUpdateRequest
 * @see com.substring.authapp.exceptions.GlobalExceptionHandler
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class UserController {

    // ===================================================================================
    // SECTION 1: Infrastructure (Fields)
    // ===================================================================================

    private final UserService userService;
    private final MessageHelper messageHelper;

    // ===================================================================================
    // SECTION 2: Administrative Provisioning (Root)
    // ===================================================================================

    /**
     * Registers a new administrative user.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates the incoming {@link AdminUserCreateRequest} using {@code @Valid} (JSR-303).
     * 2. Delegates the creation logic, including role assignment and password hashing, 
     *    to {@link UserService#createUser(AdminUserCreateRequest)}.
     * 3. Returns a sanitized {@link ManagementUserResponse} with a 201 Created status.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * If validation fails, a {@code MethodArgumentNotValidException} is triggered, which is 
     * intercepted by the {@code GlobalExceptionHandler} to provide a structured error response.
     * </p>
     *
     * @param request DTO containing new administrative user details.
     * @return ResponseEntity containing the created ManagementUserResponse and HTTP 201 status.
     */
    @PostMapping("/root/create")
    public ResponseEntity<ManagementUserResponse> createUser(@Valid @RequestBody AdminUserCreateRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(request));
    }

    /**
     * Removes a user from the system.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Identifies the user via their UUID.
     * 2. Deletes the user and associated records (e.g., refresh tokens).
     * 3. Returns a 204 No Content status upon success.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * Hard deletion is used here to ensure data privacy and compliance with "right to be forgotten" 
     * requests. Returning {@code ResponseEntity<Void>} with {@code noContent()} status 
     * ensures semantic uniformity across the entire API project.
     * </p>
     *
     * @param userId The UUID of the user to delete.
     * @return ResponseEntity with 204 No Content status.
     */
    @DeleteMapping("/root/delete/{userId}")
    public ResponseEntity<Void> deleteUserById(@PathVariable UUID userId) {
        userService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

    // ===================================================================================
    // SECTION 3: Administrative Auditing (Admin)
    // ===================================================================================

    /**
     * Retrieves a list of all users in the system.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Fetches all user entities via the {@link UserService}.
     * 2. Transforms entities into {@link ManagementUserResponse} views to ensure sensitive 
     *    data (like password hashes) is not exposed.
     * 3. Returns an iterable collection of users.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * This administrative endpoint allows for system-wide user auditing while maintaining 
     * data encapsulation through specific Response DTO mapping.
     * </p>
     *
     * @return ResponseEntity with a collection of ManagementUserResponse objects.
     */
    @GetMapping("/admin/users")
    public ResponseEntity<Iterable<ManagementUserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    /**
     * Retrieves a specific user by their unique identifier.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Extracts the {@code userId} from the path variable.
     * 2. Queries the database via the service layer.
     * 3. Returns the user profile or throws a 404 if not found.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * Utilizes {@link UserService#getUserById(UUID)}, which interacts with the 
     * {@code UserRepository} to find the entity. If the entity is absent, a 
     * {@code ResourceNotFoundException} is thrown.
     * </p>
     *
     * @param userId The unique UUID of the user.
     * @return ResponseEntity containing the found ManagementUserResponse.
     */
    @GetMapping("/admin/users/{userId}")
    public ResponseEntity<ManagementUserResponse> getUser(@PathVariable UUID userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    /**
     * Locates a user profile using their email address.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Performs a case-sensitive search for the provided email string.
     * 2. Returns the associated {@link ManagementUserResponse} if a match is found.
     * </p>
     *
     * @param emailId The email address to look up.
     * @return ResponseEntity with the found ManagementUserResponse.
     */
    @GetMapping("/admin/email/{emailId}")
    public ResponseEntity<ManagementUserResponse> getUserByEmail(@PathVariable String emailId) {
        return ResponseEntity.ok(userService.getUserByEmail(emailId));
    }

    // ===================================================================================
    // SECTION 4: Self-Service Operations (User)
    // ===================================================================================

    /**
     * Updates an existing user's profile information.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Authorization (IDOR Prevention):</b> Verifies that the {@code currentUser} 
     *    is either the owner of the account being modified or possesses administrative 
     *    privileges ({@code ROLE_ADMIN} or {@code ROLE_ROOT}).
     * 2. <b>Validation:</b> Validates the updated data in the {@link UserUpdateRequest}.
     * 3. <b>Persistence:</b> Merges the new data with the existing persistent entity.
     * 4. <b>Transformation:</b> Returns a minimalist {@link AuthUserResponse}.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * This endpoint utilizes <b>Object-Level Authorization</b>. By comparing the 
     * {@link User#getId()} of the authenticated principal against the path variable, 
     * we prevent unauthorized cross-user profile modifications.
     * </p>
     *
     * @param userId  The UUID of the user to update.
     * @param request The updated user information.
     * @param currentUser The currently authenticated user principal.
     * @return ResponseEntity with the updated AuthUserResponse.
     * @throws AccessDeniedException If a non-admin user attempts to update someone else's profile.
     */
    @PutMapping("/update/user/{userId}")
    public ResponseEntity<AuthUserResponse> updateUser(
            @PathVariable UUID userId, 
            @Valid @RequestBody UserUpdateRequest request,
            @AuthenticationPrincipal User currentUser) {

        // IDOR Protection: Check ownership or administrative status
        boolean isOwner = currentUser.getId().equals(userId);
        boolean isAdmin = currentUser.getRoles().stream()
                .anyMatch(r -> r.getName() == UserRole.ROLE_ADMIN || r.getName() == UserRole.ROLE_ROOT);

        if (!isOwner && !isAdmin) {
            throw new AccessDeniedException(messageHelper.getMessage("auth.user.access_denied"));
        }

        return ResponseEntity.ok(userService.updateUser(request, userId));
    }

    /**
     * Self-service endpoint to change password.
     *
     * @param request The password change payload.
     * @param currentUser The currently authenticated principal.
     * @return ResponseEntity with 204 No Content status.
     */
    @PostMapping("/user/me/password")
    public ResponseEntity<Void> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            @AuthenticationPrincipal User currentUser) {
        userService.changePassword(request, currentUser);
        return ResponseEntity.noContent().build();
    }

    /**
     * Self-service endpoint to delete the authenticated user's account.
     *
     * @param currentUser The currently authenticated principal.
     * @return ResponseEntity with 204 No Content status.
     */
    @DeleteMapping("/user/me")
    public ResponseEntity<Void> deleteSelfAccount(@AuthenticationPrincipal User currentUser) {
        userService.deleteUser(currentUser.getId());
        return ResponseEntity.noContent().build();
    }
}