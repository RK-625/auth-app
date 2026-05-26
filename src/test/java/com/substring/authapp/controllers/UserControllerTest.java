package com.substring.authapp.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.admin.AdminUserCreateRequest;
import com.substring.authapp.dtos.admin.ManagementUserResponse;
import com.substring.authapp.dtos.user.UserUpdateRequest;
import com.substring.authapp.exceptions.GlobalExceptionHandler;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.services.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <h1>User Controller Unit Tests</h1>
 *
 * <p>Verifies the behavior of the {@link UserController} by mocking the service layer 
 * and performing simulated HTTP requests using {@link MockMvc} in standalone mode.</p>
 */
@ExtendWith(MockitoExtension.class)
public class UserControllerTest {

    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private UserService userService;

    @Mock
    private MessageHelper messageHelper;

    @BeforeEach
    void setUp() {
        UserController userController = new UserController(userService, messageHelper);
        mockMvc = MockMvcBuilders.standaloneSetup(userController)
                .setControllerAdvice(new GlobalExceptionHandler(messageHelper))
                .build();
    }

    /**
     * Test case for successful administrative user creation.
     */
    @Test
    void createUser_WithValidPayload_ShouldReturn201Created() throws Exception {
        // Arrange
        AdminUserCreateRequest request = AdminUserCreateRequest.builder()
                .email("test@example.com")
                .password("Admin@123")
                .name("Test User")
                .build();

        ManagementUserResponse response = ManagementUserResponse.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .name("Test User")
                .build();

        when(userService.createUser(any(AdminUserCreateRequest.class))).thenReturn(response);

        // Act
        MvcResult mvcResult = mockMvc.perform(post("/api/v1/root/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andReturn();

        // Assert (using AssertJ)
        String content = mvcResult.getResponse().getContentAsString();
        ManagementUserResponse actualResponse = objectMapper.readValue(content, ManagementUserResponse.class);
        assertThat(actualResponse.getEmail()).isEqualTo("test@example.com");
        assertThat(actualResponse.getName()).isEqualTo("Test User");
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
