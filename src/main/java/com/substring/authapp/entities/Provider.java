package com.substring.authapp.entities;

/**
 * <h1>Authentication Provider Context</h1>
 *
 * <p>Enumeration of authentication identity providers supported by the system. It 
 * defines the authoritative source of truth for a user's security principal.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Discovery:</b> The identity source is identified during a local login attempt or via an OAuth2 callback.
 * 2. <b>Assignment:</b> Persisted as a {@link String} on the {@link User} entity within the <b>Persistence Context</b>.
 * 3. <b>Routing:</b> Used by the authentication manager to determine if password checks are required.
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This enum dictates the authentication strategy. Components like the 
 * {@code OAuth2SuccessHandler} utilize these values to determine if JIT (Just-In-Time) 
 * provisioning is required. Within the <b>Persistence Context</b>, these are 
 * mapped using {@code @Enumerated(EnumType.STRING)} to ensure database 
 * readability and prevent ordinal-shifting bugs.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Centralizing provider definitions ensures <b>Decoupling</b> between the 
 * authentication logic and specific provider implementations. It acts as a 
 * <b>Database Constraint</b> at the application level, ensuring only 
 * supported identity sources are permitted.
 * </p>
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
