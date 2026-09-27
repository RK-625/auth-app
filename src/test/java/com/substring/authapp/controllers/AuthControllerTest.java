package com.substring.authapp.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.auth.LoginRequest;
import com.substring.authapp.dtos.auth.SignUpInitiateRequest;
import com.substring.authapp.exceptions.GlobalExceptionHandler;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.services.AuthService;
import io.micrometer.core.instrument.MeterRegistry;
import com.substring.authapp.dtos.auth.TokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.substring.authapp.entities.User;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private AuthService authService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private MessageHelper messageHelper;

    @Mock
    private MeterRegistry meterRegistry;

    @Mock
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        AuthController authController = new AuthController(authService, authenticationManager, messageHelper, meterRegistry, userRepository);
        mockMvc = MockMvcBuilders.standaloneSetup(authController)
                .setControllerAdvice(new GlobalExceptionHandler(messageHelper))
                .build();
    }

    @Test
    void login_WithValidCredentials_ShouldReturn200Ok() throws Exception {
        LoginRequest loginRequest = new LoginRequest("test@example.com", "password123");
        TokenResponse response = TokenResponse.builder()
                .accessToken("mock-access-token")
                .build();
        
        Authentication authentication = Mockito.mock(Authentication.class);
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(authService.loginRequest(any(), any())).thenReturn(response);

        MvcResult mvcResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String content = mvcResult.getResponse().getContentAsString();
        TokenResponse actualResponse = objectMapper.readValue(content, TokenResponse.class);
        assertThat(actualResponse.accessToken()).isEqualTo("mock-access-token");
    }

    @Test
    void login_WithInvalidEmail_ShouldReturn400BadRequest() throws Exception {
        LoginRequest loginRequest = new LoginRequest("not-an-email", "password123");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_WithShortPassword_ShouldReturn400BadRequest() throws Exception {
        LoginRequest loginRequest = new LoginRequest("test@example.com", "123");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void signUpRequestFirst_WithValidPayload_ShouldReturn200Ok() throws Exception {
        SignUpInitiateRequest signUpRequest = new SignUpInitiateRequest("test@example.com");
        doNothing().when(authService).signUpRequest(any(SignUpInitiateRequest.class));

        mockMvc.perform(post("/api/v1/auth/signup/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isOk());
    }

    @Test
    void logout_ShouldReturn204NoContent() throws Exception {
        doNothing().when(authService).processLogout(any(), any(), any());

        mockMvc.perform(post("/api/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent());
    }

    @Test
    void login_WhenAccountIsLocked_ShouldReturn401AndTriggerEscalation() throws Exception {
        LoginRequest loginRequest = new LoginRequest("locked@example.com", "password123");
        User user = new User();
        user.setEmail("locked@example.com");
        user.setLockedUntil(Instant.now().plus(15, ChronoUnit.MINUTES));

        when(authenticationManager.authenticate(any())).thenThrow(new LockedException("User account is locked"));
        when(userRepository.findByEmail("locked@example.com")).thenReturn(Optional.of(user));
        when(messageHelper.getMessage(eq("auth.user.locked"), any())).thenReturn("Account locked");

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());

        verify(authService).recordFailedLoginAttempt("locked@example.com");
    }
}
