package com.substring.authapp.entities;

/**
 * <h1>Authentication Provider Context</h1>
 *
 * <p>Enumeration of authentication identity providers supported by the system.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Discovery:</b> The identity source is identified either during a local login attempt or via an OAuth2 callback.
 * 2. <b>Assignment:</b> Set on the {@link User} entity upon registration or JIT provisioning.
 * 3. <b>Routing:</b> Used by the authentication manager to determine if password checks are required (e.g., LOCAL requires password verification, OAuth2 trusts the external provider).
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This enum dictates the authentication strategy used by the system. During social logins, components like {@link com.substring.authapp.security.OAuth2SuccessHandler} use this value to register or identify returning users without prompting for a local password.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Centralizing the provider definitions ensures that adding new social login providers in the future requires minimal structural changes. It acts as a definitive whitelist of trusted identity sources.
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
