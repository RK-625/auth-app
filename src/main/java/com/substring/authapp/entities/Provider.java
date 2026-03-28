package com.substring.authapp.entities;

/**
 * Enumeration of authentication providers supported by the system.
 */
public enum Provider {
    /** Internal authentication using local email and password. */
    LOCAL, 

    /** Authentication via an external organization. */
    ORGANIZATION, 

    /** Authentication using Google OAuth2. */
    GOOGLE, 

    /** Authentication using GitHub OAuth2. */
    GITHUB, 

    /** Authentication using Facebook OAuth2. */
    FACEBOOK
}
