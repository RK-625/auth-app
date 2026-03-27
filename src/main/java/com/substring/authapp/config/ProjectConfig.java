package com.substring.authapp.config;

import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;

/**
 * General project configuration for cross-cutting concerns.
 */
@Configuration
public class ProjectConfig {

    /**
     * Bean for object-to-object mapping (DTOs to Entities and vice-versa).
     */
    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    /**
     * Configures the message source for localized error messages.
     * Looks for 'messages.properties' in the classpath.
     */
    @Bean
    public MessageSource messageSource() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setBasename("messages");
        return messageSource;
    }
}
