package com.substring.authapp.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.admin.AdminUserCreateRequest;
import com.substring.authapp.dtos.admin.ManagementUserResponse;
import com.substring.authapp.dtos.user.UserUpdateRequest;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.RateLimiterService;
import com.substring.authapp.services.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * <h1>User Controller Integration Tests</h1>
 *
 * <p>Verifies the behavior of the {@link UserController} by mocking the service layer 
 * and performing simulated HTTP requests using {@link MockMvc}. Security filters 
 * are disabled to focus on controller logic and validation rules.</p>
 */
@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
public class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private MessageHelper messageHelper;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private RateLimiterService rateLimiterService;

    /**
     * Test case for successful administrative user creation.
     */
    @Test
    void createUser_WithValidPayload_ShouldReturn201Created() throws Exception {
        // Arrange
        AdminUserCreateRequest request = AdminUserCreateRequest.builder()
                .email("test@example.com")
                .password("password123")
                .name("Test User")
                .build();

        ManagementUserResponse response = ManagementUserResponse.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .name("Test User")
                .build();

        when(userService.createUser(any(AdminUserCreateRequest.class))).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/v1/root/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.name").value("Test User"));
    }

    /**
     * Test case for successful user deletion.
     */
    @Test
    void deleteUserById_ShouldReturn204NoContent() throws Exception {
        // Arrange
        UUID userId = UUID.randomUUID();
        doNothing().when(userService).deleteUser(any(UUID.class));

        // Act & Assert
        mockMvc.perform(delete("/api/v1/root/delete/{userId}", userId))
                .andExpect(status().isNoContent());
    }

    /**
     * Test case for validation failure when the name exceeds the maximum length.
     */
    @Test
    void updateUser_WithNameTooLong_ShouldReturn400BadRequest() throws Exception {
        // Arrange
        UUID userId = UUID.randomUUID();
        String longName = "A".repeat(101);
        UserUpdateRequest request = UserUpdateRequest.builder()
                .name(longName)
                .build();

        // Act & Assert
        mockMvc.perform(put("/api/v1/update/user/{userId}", userId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
}
