package com.substring.authapp.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.auth.LoginRequest;
import com.substring.authapp.dtos.auth.SignUpInitiateRequest;
import com.substring.authapp.services.EmailService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private EmailService emailService;

    @MockitoBean
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @MockitoBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @Test
    void unauthenticatedRequest_ToProtectedEndpoint_ShouldReturn401Unauthorized() throws Exception {
        mockMvc.perform(get("/api/v1/admin/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unauthenticatedRequest_ToPublicEndpoint_ShouldReturn200Ok() throws Exception {
        SignUpInitiateRequest request = new SignUpInitiateRequest("integration@test.com");
        
        mockMvc.perform(post("/api/v1/auth/signup/request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    void rateLimiter_ShouldBlockRequestsAfterThreshold() throws Exception {
        LoginRequest request = new LoginRequest("attacker@test.com", "password123");
        String content = objectMapper.writeValueAsString(request);

        // Perform 10 requests (the limit) using a unique IP to avoid interference
        String clientIp = "192.168.1.100";
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("X-Forwarded-For", clientIp)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(content))
                    .andExpect(status().isUnauthorized());
        }

        // 11th request should be blocked by rate limiter
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Forwarded-For", clientIp)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(content))
                .andExpect(status().isTooManyRequests());
    }
}
