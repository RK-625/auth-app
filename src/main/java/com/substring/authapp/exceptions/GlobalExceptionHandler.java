package com.substring.authapp.exceptions;

import com.substring.authapp.dtos.common.ApiError;
import com.substring.authapp.helpers.MessageHelper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.security.auth.login.CredentialExpiredException;
import java.util.stream.Collectors;

/**
 * <h1>Global Infrastructure for Exception Remediation</h1>
 *
 * <p>This class serves as the centralized interceptor for all unhandled exceptions thrown across the application.
 * By utilizing {@link RestControllerAdvice}, it ensures that every error response follows a standardized
 * {@link ApiError} format, shielding the client from raw stack traces and internal system details.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Interception:</b> Catches unhandled exceptions thrown from the Controller layer.
 * 2. <b>Normalization:</b> Maps specific exception types to standardized HTTP status codes.
 * 3. <b>Suppression:</b> Replaces internal system messages with user-friendly, secure descriptions.
 * 4. <b>Transformation:</b> Wraps the error metadata into an {@link ApiError} DTO for client consumption.
 * </p>
 *
 * <p><b>Behind the Scenes (Exception Resolution Handshake):</b>
 * Spring's {@code ExceptionHandlerExceptionResolver} scans this class for {@link ExceptionHandler} annotations 
 * during application startup. When an exception is thrown during a request, the resolver performs a 
 * <b>Type Match</b> against the annotated methods to delegate the error handling logic.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Centralized error handling promotes "fail-fast" behavior while maintaining a clean API contract.
 * It prevents <b>Information Leakage</b> by ensuring that internal implementation details (like 
 * SQL syntax errors or class names) are never exposed to external consumers.
 * </p>
 *
 * @author Gemini CLI
 * @see ApiError
 */
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    // ===================================================================================
    // SECTION 1: Infrastructure (Fields)
    // ===================================================================================

    private final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final MessageHelper messageHelper;

    // ===================================================================================
    // SECTION 2: Security Exceptions (Auth & Authz)
    // ===================================================================================

    /**
     * Authorization and Access Control Failures.
     * 
     * <p><b>Triggering Conditions:</b>
     * Occurs when an authenticated user attempts to access a resource for which they do 
     * not possess the required authorities (e.g., a USER attempting to access ROOT endpoints).</p>
     * 
     * <p><b>Design Rationale:</b>
     * Explicitly catching {@link AccessDeniedException} ensures that the client receives 
     * a semantic 403 Forbidden status instead of a generic 500 error, facilitating 
     * accurate frontend permission handling.</p>
     * 
     * @param e The access denied exception.
     * @param request The current web request.
     * @return A standardized 403 error response.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleAccessDeniedException(AccessDeniedException e, HttpServletRequest request) {
        logger.warn("Authorization failure: Access Denied for URI {}", request.getRequestURI());
        String message = messageHelper.getMessage("auth.user.access_denied");
        ApiError apiError = ApiError.of(HttpStatus.FORBIDDEN.value(), "Forbidden", message, request.getRequestURI());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(apiError);
    }

    /**
     * Identity and Access Management Failures.
     *
     * <p><b>Triggering Conditions:</b>
     * Occurs when credentials (username/password) are incorrect, an account is disabled,
     * or a security token has expired or is cryptographically invalid.</p>
     *
     * <p><b>Behind the Scenes:</b>
     * This handler covers a broad range of {@code org.springframework.security.core.AuthenticationException}
     * subclasses. By returning a 401 Unauthorized, it signals the client's interceptors 
     * to trigger a re-authentication or token refresh flow.</p>
     *
     * <p><b>Developer Note:</b>
     * This method suppresses specific security provider details to prevent attackers from 
     * gaining insights into the internal authentication mechanics.
     * </p>
     *
     * @param e The authentication exception.
     * @param request The current web request.
     * @return A standardized 401 error response.
     */
    @ExceptionHandler({
        BadCredentialsException.class, 
        UsernameNotFoundException.class, 
        CredentialExpiredException.class, 
        DisabledException.class
    })
    public ResponseEntity<ApiError> handleAuthExceptions(Exception e, HttpServletRequest request) {
        logger.warn("Authentication failure: {}", e.getMessage());
        ApiError apiError = ApiError.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized", e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(apiError);
    }

    // ===================================================================================
    // SECTION 3: Data & Validation Exceptions
    // ===================================================================================

    /**
     * Database Integrity and Constraint Violations.
     *
     * <p><b>Triggering Conditions:</b>
     * Most commonly triggered by a {@code Unique Constraint} violation, such as attempting
     * to register an email address that already exists in the {@code users} table.</p>
     *
     * <p><b>Behind the Scenes (Security Suppression):</b>
     * Raw {@link DataIntegrityViolationException} messages often contain sensitive SQL information.
     * This handler intercepts the Hibernate-level exception and replaces it with a 
     * generic "Conflict" status (409).</p>
     *
     * <p><b>Design Rationale:</b>
     * Suppressing raw SQL details is a critical security measure to prevent <b>Database 
     * Fingerprinting</b> and <b>SQL Injection</b> reconnaissance.
     * </p>
     *
     * @param e The JPA/Hibernate integrity exception.
     * @param request The current web request.
     * @return A standardized 409 Conflict error response.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> handleDataIntegrityViolationException(DataIntegrityViolationException e, HttpServletRequest request) {
        logger.error("Database integrity violation: {}", e.getMessage());
        String message = messageHelper.getMessage("user.register.email_exists");
        ApiError apiError = ApiError.of(HttpStatus.CONFLICT.value(), "Conflict", message, request.getRequestURI());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(apiError);
    }

    /**
     * Input Validation Failures (@Valid).
     *
     * <p><b>Triggering Conditions:</b>
     * Triggered when a request body fails JSR-303/JSR-380 validation (e.g., {@code @NotBlank}, {@code @Email}, {@code @Size}).</p>
     *
     * <p><b>Behind the Scenes:</b>
     * This handler extracts all field-level errors from the {@code BindingResult} object 
     * provided by the {@code MethodArgumentNotValidException}. It flattens these 
     * into a single comma-separated string for the {@link ApiError} message.</p>
     *
     * @param e The validation exception.
     * @param request The current web request.
     * @return A standardized 400 Bad Request error response.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidationException(MethodArgumentNotValidException e, HttpServletRequest request) {
        String errors = e.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .collect(Collectors.joining(", "));
        
        ApiError apiError = ApiError.of(HttpStatus.BAD_REQUEST.value(), messageHelper.getMessage("system.validation.failure"), errors, request.getRequestURI());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiError);
    }

    /**
     * Domain Resource Absence.
     *
     * <p><b>Triggering Conditions:</b>
     * Occurs when a requested entity (User, Role, Token) cannot be found in the database by its identifier.</p>
     *
     * <p><b>Design Rationale:</b>
     * Distinguishing between "Endpoint not found" (404 handled by the container) and 
     * "Resource data not found" (404 handled here) provides more granular feedback 
     * for frontend developers and API consumers.</p>
     *
     * @param e The resource not found exception.
     * @param request The current web request.
     * @return A standardized 404 Not Found error response.
     * @see ResourceNotFoundException
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiError> handleResourceNotFoundException(ResourceNotFoundException e, HttpServletRequest request) {
        ApiError apiError = ApiError.of(HttpStatus.NOT_FOUND.value(), "Not Found", e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(apiError);
    }

    /**
     * Semantic and Business Rule Violations.
     *
     * <p><b>Triggering Conditions:</b>
     * Triggered when a request is syntactically correct but violates business logic (e.g., invalid OTP,
     * illegal state transition).</p>
     *
     * @param e The illegal argument exception.
     * @param request The current web request.
     * @return A standardized 400 Bad Request error response.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleIllegalArgumentException(IllegalArgumentException e, HttpServletRequest request) {
        ApiError apiError = ApiError.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiError);
    }

    /**
     * Concurrent Access and Race Condition Failures.
     *
     * <p><b>Triggering Conditions:</b>
     * Triggered by JPA's <b>Optimistic Locking</b> mechanism when two concurrent requests 
     * attempt to modify the same record (e.g., simultaneous refresh token rotation).</p>
     *
     * <p><b>Design Rationale:</b>
     * By catching {@link ObjectOptimisticLockingFailureException}, we provide a 
     * semantic 409 Conflict status. This allows the client to implement a 
     * transparent retry strategy or inform the user that their session is being updated.</p>
     *
     * @param e The concurrency exception.
     * @param request The current web request.
     * @return A standardized 409 Conflict error response.
     */
    @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
    public ResponseEntity<ApiError> handleOptimisticLockingFailureException(ObjectOptimisticLockingFailureException e, HttpServletRequest request) {
        logger.warn("Concurrency conflict detected: {}", e.getMessage());
        String message = messageHelper.getMessage("system.error.concurrency_conflict");
        ApiError apiError = ApiError.of(HttpStatus.CONFLICT.value(), "Conflict", message, request.getRequestURI());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(apiError);
    }

    // ===================================================================================
    // SECTION 4: Fallback Exceptions (System Errors)
    // ===================================================================================

    /**
     * Unhandled Internal System Failures.
     *
     * <p><b>Triggering Conditions:</b>
     * The final safety net for any {@link Exception} that hasn't been explicitly caught by a more specific handler.</p>
     *
     * <p><b>Behind the Scenes:</b>
     * In production, this handler MUST NOT leak specific exception details. It logs the full stack trace
     * internally via SLF4J for debugging but returns a generic "Internal Server Error" to the client.</p>
     *
     * @param e The unhandled exception.
     * @param request The current web request.
     * @return A standardized 500 Internal Server Error response.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGenericException(Exception e, HttpServletRequest request) {
        logger.error("Unhandled exception occurred: ", e);
        ApiError apiError = ApiError.of(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal Server Error", messageHelper.getMessage("system.error.unexpected"), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiError);
    }
}


