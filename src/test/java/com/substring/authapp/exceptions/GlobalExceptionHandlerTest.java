package com.substring.authapp.exceptions;

import com.substring.authapp.helpers.MessageHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    private MockMvc mockMvc;

    @Mock
    private MessageHelper messageHelper;

    @InjectMocks
    private GlobalExceptionHandler globalExceptionHandler;

    @RestController
    static class TestController {
        @GetMapping("/test/optimistic-lock")
        public void triggerOptimisticLock() {
            throw new ObjectOptimisticLockingFailureException("User", "id");
        }

        @GetMapping("/test/resource-not-found")
        public void triggerResourceNotFound() {
            throw new ResourceNotFoundException("Resource not found");
        }

        @GetMapping("/test/data-integrity")
        public void triggerDataIntegrity() {
            throw new DataIntegrityViolationException("SQL Error: Duplicate entry 'test@test.com' for key 'users.UK_email'");
        }

        @GetMapping("/test/access-denied")
        public void triggerAccessDenied() {
            throw new AccessDeniedException("Access Denied");
        }

        @GetMapping("/test/bad-credentials")
        public void triggerBadCredentials() {
            throw new BadCredentialsException("Bad Credentials");
        }

        @GetMapping("/test/runtime-error")
        public void triggerRuntimeError() {
            throw new RuntimeException("Unexpected error");
        }
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new TestController())
                .setControllerAdvice(globalExceptionHandler)
                .build();
    }

    @Test
    void whenObjectOptimisticLockingFailureException_thenReturns409Conflict() throws Exception {
        when(messageHelper.getMessage(anyString())).thenReturn("Concurrency conflict occurred");

        mockMvc.perform(get("/test/optimistic-lock")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Concurrency conflict occurred"));
    }

    @Test
    void whenResourceNotFoundException_thenReturns404NotFound() throws Exception {
        mockMvc.perform(get("/test/resource-not-found")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Resource not found"));
    }

    @Test
    void whenDataIntegrityViolationException_thenReturns409AndDoesNotLeakDetails() throws Exception {
        when(messageHelper.getMessage("user.register.email_exists")).thenReturn("Email already exists");

        mockMvc.perform(get("/test/data-integrity")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists"));
    }

    @Test
    void whenAccessDeniedException_thenReturns403Forbidden() throws Exception {
        mockMvc.perform(get("/test/access-denied"))
                .andExpect(status().isForbidden());
    }

    @Test
    void whenBadCredentialsException_thenReturns401Unauthorized() throws Exception {
        mockMvc.perform(get("/test/bad-credentials"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void whenRuntimeException_thenReturns500InternalServerError() throws Exception {
        when(messageHelper.getMessage("system.error.unexpected")).thenReturn("Internal server error");

        mockMvc.perform(get("/test/runtime-error"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").value("Internal server error"));
    }
}
