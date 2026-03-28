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
 * REST controller for managing system users.
 * Provides endpoints for standard CRUD operations and search by email.
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * Registers a new user account.
     */
    @PostMapping("/root/create")
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(userDto));
    }

    /**
     * Returns a list of all users in the system.
     */
    @GetMapping("/admin/users")
    public ResponseEntity<Iterable<UserDto>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    /**
     * Retrieves a single user profile by their unique ID.
     */
    @GetMapping("/admin/users/{userId}")
    public ResponseEntity<UserDto> getUser(@PathVariable UUID userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    /**
     * Finds a user profile by their email address.
     */
    @GetMapping("/admin/email/{emailId}")
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String emailId) {
        return ResponseEntity.ok(userService.getUserByEmail(emailId));
    }

    /**
     * Permanently deletes a user account from the system.
     */
    @DeleteMapping("/root/delete/{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteUserById(@PathVariable UUID userId) {
        userService.deleteUser(userId);
    }

    /**
     * Updates profile information for an existing user.
     */
    @PutMapping("/update/user/{userId}")
    public ResponseEntity<UserDto> updateUser(@PathVariable UUID userId, @Valid @RequestBody UserDto userDto) {
        return ResponseEntity.ok(userService.updateUser(userDto, userId));
    }
}