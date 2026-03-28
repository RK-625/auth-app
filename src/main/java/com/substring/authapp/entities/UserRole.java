package com.substring.authapp.entities;

/**
 * Enumeration of available user roles within the application.
 * These are used to control access to various endpoints and features.
 */
public enum UserRole {
    /** Regular user with standard access permissions. */
    ROLE_USER, 

    /** Administrator with elevated access permissions. */
    ROLE_ADMIN, 

    /** Root user with full system access. */
    ROLE_ROOT;
}
