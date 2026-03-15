package com.substring.authapp.exceptions;


import com.substring.authapp.dtos.ApiError;
import com.substring.authapp.dtos.ErrorResponse;
import jakarta.security.auth.message.AuthException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpClientErrorException;

import javax.security.auth.login.CredentialExpiredException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    public final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler({BadCredentialsException.class, UsernameNotFoundException.class, CredentialExpiredException.class, DisabledException.class})
    public ResponseEntity<ApiError> handleAuthExceptions(Exception e, HttpServletRequest request){
        logger.info("Exception: {}", e.getMessage());
        ApiError apiError = ApiError.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", e.getMessage(), request.getRequestURI());
        return ResponseEntity.badRequest().body(apiError);
    }
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(ResourceNotFoundException exception){
        ErrorResponse errorResponse = new ErrorResponse(exception.getMessage(), HttpStatus.NOT_FOUND, HttpStatus.NOT_FOUND.value());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException exception){
        ErrorResponse errorResponse = new ErrorResponse(exception.getMessage(), HttpStatus.BAD_REQUEST, HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }
}
