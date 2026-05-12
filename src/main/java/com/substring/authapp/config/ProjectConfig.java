package com.substring.authapp.config;

import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;

/**
 * <h1>Cross-Cutting Infrastructure Configuration</h1>
 * 
 * <p>Centralizes the definition of generic beans that support the application's mapping 
 * and messaging layers. This class acts as the "Centralized Infrastructure" hub, 
 * ensuring that low-level utility services are decoupled from the business logic.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Mapping:</b> Initializes {@link ModelMapper} for automated DTO-Entity handshakes.
 * 2. <b>Localization:</b> Configures {@link MessageSource} for multi-lingual error resolution.
 * 3. <b>Bootstrap:</b> Registers these infrastructure beans for project-wide injection.
 * </p>
 * 
 * <p><b>Behind the Scenes (Infrastructure Handshake):</b>
 * This configuration manages critical bean handshakes. The {@link ModelMapper} is 
 * consumed by the {@link com.substring.authapp.helpers.UserHelper} to bridge the 
 * gap between the <b>Persistence Context</b> and the API layer. Simultaneously, 
 * the {@link MessageSource} is utilized by the {@link com.substring.authapp.helpers.MessageHelper} 
 * to provide localized "Fail-Fast" validation feedback. This feedback is then 
 * serialized by the {@link com.substring.authapp.exceptions.GlobalExceptionHandler} 
 * into a {@link com.substring.authapp.dtos.common.ApiError} DTO, completing the 
 * <b>Error Communication Handshake</b>.</p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * Centralizing these infrastructure beans prevents "Configuration Drift" and ensures 
 * a consistent mapping and messaging strategy across all service layers. It follows 
 * the <b>Single Responsibility Principle</b> by isolating utility instantiation 
 * from business logic execution.
 * </p>
 */
@Configuration
public class ProjectConfig {

    // ===================================================================================
    // SECTION 1: Data Transformation (Mapping)
    // ===================================================================================

    /**
     * <h1>DTO Projection Engine</h1>
     * 
     * <p>Provides a singleton instance of {@link ModelMapper} to automate the 
     * copying of fields between DTOs and persistent Entities.</p>
     * 
     * <p><b>Behind the Scenes (Mapping Handshake):</b>
     * This bean is used by {@link com.substring.authapp.helpers.UserHelper} and 
     * {@link com.substring.authapp.security.OAuth2SuccessHandler} to ensure 
     * that internal database IDs and sensitive fields are not automatically 
     * leaked to the presentation layer during response assembly. It facilitates 
     * the <b>Domain-to-DTO Handshake</b> by strictly mapping only authorized fields.</p>
     * 
     * @return A configured {@link ModelMapper} bean.
     */
    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    // ===================================================================================
    // SECTION 2: Internationalization (Messaging)
    // ===================================================================================

    /**
     * <h1>Centralized Messaging Authority</h1>
     * 
     * <p>Configures the primary engine for retrieving localized strings.</p>
     * 
     * <p><b>Behind the Scenes (Localization Handshake):</b>
     * It looks for a bundle named {@code messages} (specifically {@code messages.properties}) 
     * on the classpath. It is utilized by the {@link com.substring.authapp.helpers.MessageHelper} 
     * to provide localized "Fail-Fast" validation messages. This establishes a 
     * <b>User-Centric Handshake</b> where technical errors are translated into 
     * human-readable feedback based on the client's browser locale.</p>
     * 
     * @return A configured {@link MessageSource} bean.
     */
    @Bean
    public MessageSource messageSource() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setBasename("messages");
        return messageSource;
    }
}
