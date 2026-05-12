package com.substring.authapp.exceptions;

/**
 * <h1>Domain Resource Absence Exception</h1>
 * 
 * <p><b>Triggering Conditions:</b>
 * Occurs when a specific entity (e.g., User, Role, or Token) is requested by its 
 * identifier but does not exist within the <b>Persistence Context</b>.</p>
 * 
 * <p><b>Developer Note:</b>
 * This exception is caught by the {@link GlobalExceptionHandler} and mapped to a 
 * 404 Not Found response. It ensures that the client receives specific 
 * feedback when a resource is missing, distinct from a generic system failure.
 * </p>
 * 
 * @see GlobalExceptionHandler#handleResourceNotFoundException(ResourceNotFoundException, jakarta.servlet.http.HttpServletRequest)
 */
public class ResourceNotFoundException extends RuntimeException {
    
    /**
     * Constructs a new exception with a specific error message.
     * @param message The detailed reason for the failure.
     */
    public ResourceNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructs a new exception with a generic default message.
     */
    public ResourceNotFoundException(){
        super("The Resource is NOT found !!");
    }
}
