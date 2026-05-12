package com.substring.authapp.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.auth.LoginRequest;
import com.substring.authapp.dtos.auth.SignUpInitiateRequest;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.security.JwtService;
import com.substring.authapp.services.AuthService;
import com.substring.authapp.services.RateLimiterService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private MessageHelper messageHelper;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private RateLimiterService rateLimiterService;

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
}
