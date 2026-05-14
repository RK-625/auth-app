package com.substring.authapp.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.auth.SignUpCompleteRequest;
import com.substring.authapp.dtos.auth.SignUpInitiateRequest;
import com.substring.authapp.dtos.auth.SignUpVerifyRequest;
import com.substring.authapp.entities.SignUpObject;
import com.substring.authapp.entities.User;
import com.substring.authapp.repositories.SignUpObjectRepository;
import com.substring.authapp.repositories.UserRepository;
import com.substring.authapp.services.EmailService;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class FullSignupHandshakeTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SignUpObjectRepository signUpObjectRepository;

    @Autowired
    private UserRepository userRepository;

    @MockitoBean
    private EmailService emailService;

    @MockitoBean
    private org.springframework.security.oauth2.client.OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @MockitoBean
    private org.springframework.security.oauth2.client.registration.ClientRegistrationRepository clientRegistrationRepository;

    @BeforeEach
    void setUp() {
        signUpObjectRepository.deleteAll();
        userRepository.deleteAll();
        org.mockito.Mockito.lenient().doNothing().when(emailService).sendSignUpOtp(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void fullSignupJourney_ShouldSuccessfullyProvisionUser() throws Exception {
        String testEmail = "newuser@example.com";
        String testPassword = "SecurePass123!";

        // Phase 1: POST /api/v1/auth/signup/request
        SignUpInitiateRequest initiateRequest = new SignUpInitiateRequest(testEmail);
        mockMvc.perform(post("/api/v1/auth/signup/request")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(initiateRequest)))
                .andExpect(status().isOk());

        Optional<SignUpObject> stagingOpt = signUpObjectRepository.findByEmail(testEmail);
        assertThat(stagingOpt).isPresent();
        SignUpObject stagingObj = stagingOpt.get();
        String otp = stagingObj.getOtp();
        assertThat(otp).isNotBlank();

        // Phase 2: POST /api/v1/auth/signup/verifyotp (Note: The URL might be /api/v1/auth/signup/verifyotp)
        SignUpVerifyRequest verifyRequest = new SignUpVerifyRequest(testEmail, otp);
        MvcResult result = mockMvc.perform(post("/api/v1/auth/signup/verifyotp")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(verifyRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        String signUpTokenStr = JsonPath.read(responseBody, "$.token");
        assertThat(signUpTokenStr).isNotBlank();

        // Phase 3: POST /api/v1/auth/signup/verifytoken
        SignUpCompleteRequest completeRequest = new SignUpCompleteRequest(testEmail, otp, signUpTokenStr, testPassword);
        mockMvc.perform(post("/api/v1/auth/signup/verifytoken")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(completeRequest)))
                .andExpect(status().isOk());

        // Assertion: Verify User is provisioned
        Optional<User> userOpt = userRepository.findByEmail(testEmail);
        assertThat(userOpt).isPresent();
        User provisionedUser = userOpt.get();
        assertThat(provisionedUser.getEmail()).isEqualTo(testEmail);
        assertThat(provisionedUser.getPassword()).isNotEqualTo(testPassword); // Should be hashed
        
        // Assertion: Verify SignUpObject is removed
        assertThat(signUpObjectRepository.findByEmail(testEmail)).isEmpty();
    }
}
