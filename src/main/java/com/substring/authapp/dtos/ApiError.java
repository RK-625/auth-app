package com.substring.authapp.dtos;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

/**
 * Data Transfer Object representing an API error.
 * Used to provide consistent error responses across the application.
 * 
 * @param status    The HTTP status code.
 * @param error     The short error name or status text.
 * @param message   A detailed error message.
 * @param path      The request path that triggered the error.
 * @param timestamp The time when the error occurred, in UTC.
 */
public record ApiError(int status, String error, String message, String path, OffsetDateTime timestamp) {

    /**
     * Factory method to create an {@link ApiError} with the current UTC timestamp.
     * 
     * @param status  The HTTP status code.
     * @param error   The short error name.
     * @param message The detailed message.
     * @param path    The request path.
     * @return a new ApiError instance.
     */
    public static ApiError of(int status, String error, String message, String path) {
        return new ApiError(status, error, message, path, OffsetDateTime.now(ZoneOffset.UTC));
    }
}
