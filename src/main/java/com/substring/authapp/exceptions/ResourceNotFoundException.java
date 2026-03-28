package com.substring.authapp.exceptions;

public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
    public ResourceNotFoundException(){
        super("The Resource is NOT found !!");
    }
}
