package com.substring.authapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

/**
 * Configuration for external API clients used by different social providers.
 */
@Configuration
public class ProviderConfig {

    /**
     * Configures the RestClient specifically for the GitHub API.
     * Includes mandatory headers like User-Agent and API versioning.
     */
    @Bean
    public RestClient githubRestClient(RestClient.Builder restClientBuilder) {
        return restClientBuilder.baseUrl("https://api.github.com")
                .defaultHeader("Accept", "application/vnd.github+json")
                .defaultHeader("User-Agent", "Bat-Security")
                .defaultHeader("X-GitHub-Api-Version", "2022-11-28")
                .build();
    }
}
