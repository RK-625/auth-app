package com.substring.authapp.exceptions;

import com.substring.authapp.dtos.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.security.auth.login.CredentialExpiredException;
import java.util.stream.Collectors;

/**
 * Centralized exception handling for the entire application.
 * Standardizes error responses using the ApiError DTO.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Handles common authentication and authorization failures.
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

    /**
     * Handles database constraint violations (e.g., unique email constraint).
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> handleDataIntegrityViolationException(DataIntegrityViolationException e, HttpServletRequest request) {
        logger.error("Database integrity violation: {}", e.getMessage());
        // For security, don't expose raw SQL details, but give a hint
        String message = "Database conflict: This record (likely email) already exists.";
        ApiError apiError = ApiError.of(HttpStatus.CONFLICT.value(), "Conflict", message, request.getRequestURI());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(apiError);
    }

    /**
     * Handles Bean Validation failures (@Valid, @NotNull, etc).
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidationException(MethodArgumentNotValidException e, HttpServletRequest request) {
        String errors = e.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .collect(Collectors.joining(", "));
        
        ApiError apiError = ApiError.of(HttpStatus.BAD_REQUEST.value(), "Validation Failed", errors, request.getRequestURI());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiError);
    }

    /**
     * Handles cases where a requested resource is missing.
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiError> handleResourceNotFoundException(ResourceNotFoundException e, HttpServletRequest request) {
        ApiError apiError = ApiError.of(HttpStatus.NOT_FOUND.value(), "Not Found", e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(apiError);
    }

    /**
     * Handles invalid client requests or validation failures.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleIllegalArgumentException(IllegalArgumentException e, HttpServletRequest request) {
        ApiError apiError = ApiError.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", e.getMessage(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(apiError);
    }

    /**
     * Catch-all handler for any unhandled internal server errors.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGenericException(Exception e, HttpServletRequest request) {
        logger.error("Unhandled exception occurred: ", e);
        ApiError apiError = ApiError.of(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal Server Error", "An unexpected error occurred", request.getRequestURI());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(apiError);
    }
}
