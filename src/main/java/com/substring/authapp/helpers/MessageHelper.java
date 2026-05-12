package com.substring.authapp.helpers;

import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

/**
 * <h1>Localization & Messaging Bridge</h1>
 *
 * <p>A utility component that centralizes the retrieval of localized messages from the 
 * application's resource bundles (e.g., {@code messages.properties}). It ensures that 
 * error messages and user-facing text are dynamically translated based on the client's locale.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Resolution:</b> Intercepts requests for a specific message key.
 * 2. <b>Contextualization:</b> Identifies the current request's locale via {@link LocaleContextHolder}.
 * 3. <b>Extraction:</b> Fetches the appropriate translated string from the configured {@link MessageSource}.
 * 4. <b>Formatting:</b> Optionally injects dynamic arguments into the message string.</p>
 *
 * <p><b>Behind the Scenes (Thread-Local Context):</b>
 * The {@link LocaleContextHolder} uses a {@code ThreadLocal} strategy to store the locale 
 * for the current HTTP request thread. This means the helper doesn't need to explicitly 
 * pass the {@code HttpServletRequest} around; Spring automatically parses the {@code Accept-Language} 
 * header and binds it to the thread context before the controller is even reached.</p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Hardcoding error messages directly into exception throws makes internationalization (i18n) 
 * impossible. By using this helper, the service layer remains clean and decoupled from 
 * presentation-layer concerns, adhering strictly to the Single Responsibility Principle.</p>
 * 
 * @author Gemini CLI
 * @see org.springframework.context.MessageSource
 */
@Component
@RequiredArgsConstructor
public class MessageHelper {

    // ===================================================================================
    // SECTION 1: Infrastructure (Fields)
    // ===================================================================================

    private final MessageSource messageSource;

    // ===================================================================================
    // SECTION 2: Localized Resolution (Public)
    // ===================================================================================

    /**
     * <h1>Dynamic Message Resolver</h1>
     * 
     * <p>Retrieves a localized message for a given key using the current thread's locale.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. Extracts the {@link java.util.Locale} from the thread-local context.
     * 2. Queries the {@link MessageSource} for the matching property key.
     * 3. Returns the translated string or throws {@code NoSuchMessageException} if missing.</p>
     * 
     * @param key The property key (e.g., "auth.forget.otp_invalid").
     * @return The localized string.
     */
    public String getMessage(String key) {
        return messageSource.getMessage(key, null, LocaleContextHolder.getLocale());
    }

    /**
     * <h1>Formatted Message Resolver</h1>
     * 
     * <p>Retrieves a localized message and injects dynamic arguments into positional placeholders.</p>
     * 
     * <p><b>Design Rationale:</b>
     * Allows for rich, dynamic feedback (e.g., "Verification code for {0} is invalid") while 
     * maintaining full translation support.</p>
     * 
     * @param key The property key.
     * @param args Dynamic values to inject into placeholders (e.g., "{0}").
     * @return The formatted and localized string.
     */
    public String getMessage(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }
}