package com.substring.authapp.controllers;

import com.substring.authapp.dtos.UserDto;
import com.substring.authapp.services.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
 * 4. Transforms internal entities into {@link UserDto} objects for secure external transmission.
 * </p>
 *
 * <p><b>Behind the Scenes:</b>
 * This controller leverages Spring's {@code DispatcherServlet} for request routing 
 * and {@code RequestMappingHandlerMapping} to map URLs to specific methods. 
 * Dependency injection is handled via constructor injection, facilitated by Lombok's 
 * {@link RequiredArgsConstructor}, ensuring that the {@link UserService} is 
 * immutable and reliably provided at runtime.
 * </p>
 *
 * <p><b>Design Rationale:</b>
 * Centralizes user-related operations while enforcing strict validation rules 
 * via JSR-303 annotations. This prevents malformed data from reaching the 
 * persistence layer and ensures consistent API responses.
 * </p>
 *
 * @author Gemini CLI
 * @see com.substring.authapp.services.UserService
 * @see com.substring.authapp.dtos.UserDto
 * @see com.substring.authapp.exceptions.GlobalExceptionHandler
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * Registers a new administrative user.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates the incoming {@link UserDto} using {@code @Valid} (JSR-303).
     * 2. Delegates the creation logic, including role assignment and password hashing, to {@link UserService#createUser(UserDto)}.
     * 3. Returns the persisted user object with a 201 Created status.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * If validation fails, a {@code MethodArgumentNotValidException} is triggered, which is 
     * intercepted by the {@code GlobalExceptionHandler} to provide a structured error response.
     * </p>
     *
     * @param userDto DTO containing new user details.
     * @return ResponseEntity containing the created UserDto and HTTP 201 status.
     */
    @PostMapping("/root/create")
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(userDto));
    }

    /**
     * Retrieves a list of all users in the system.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Fetches all user entities via the {@link UserService}.
     * 2. Transforms entities into DTOs to ensure sensitive data (like password hashes) is not exposed.
     * 3. Returns an iterable collection of users.
     * </p>
     *
     * <p><b>Design Rationale:</b>
     * This administrative endpoint allows for system-wide user auditing while maintaining 
     * data encapsulation through DTO mapping.
     * </p>
     *
     * @return ResponseEntity with a collection of UserDto objects.
     */
    @GetMapping("/admin/users")
    public ResponseEntity<Iterable<UserDto>> getAllUsers() {
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
     * @return ResponseEntity containing the found UserDto.
     */
    @GetMapping("/admin/users/{userId}")
    public ResponseEntity<UserDto> getUser(@PathVariable UUID userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    /**
     * Locates a user profile using their email address.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Performs a case-sensitive search for the provided email string.
     * 2. Returns the associated user DTO if a match is found.
     * </p>
     *
     * @param emailId The email address to look up.
     * @return ResponseEntity with the found UserDto.
     */
    @GetMapping("/admin/email/{emailId}")
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String emailId) {
        return ResponseEntity.ok(userService.getUserByEmail(emailId));
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

    /**
     * Updates an existing user's profile information.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Validates the updated data in the {@link UserDto}.
     * 2. Merges the new data with the existing persistent entity.
     * 3. Saves the updated entity and returns the new state.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * The {@code @PutMapping} ensures idempotency. The service layer manages the 
     * transition of the entity from detached/persistent states during the update process.
     * </p>
     *
     * @param userId  The UUID of the user to update.
     * @param userDto The updated user information.
     * @return ResponseEntity with the updated UserDto.
     */
    @PutMapping("/update/user/{userId}")
    public ResponseEntity<UserDto> updateUser(@PathVariable UUID userId, @Valid @RequestBody UserDto userDto) {
        return ResponseEntity.ok(userService.updateUser(userDto, userId));
    }
}