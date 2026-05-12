package com.substring.authapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

/**
 * <h1>External Service Integration Configuration</h1>
 * 
 * <p>Centralizes the definition of HTTP clients used for back-channel communication 
 * with external Identity Providers (IdPs). This configuration ensures that 
 * outbound requests follow the strict security and versioning requirements 
 * of third-party APIs.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Discovery:</b> Injects the standard Spring {@link RestClient.Builder}.
 * 2. <b>Customization:</b> Appends mandatory security headers (User-Agent, API Version).
 * 3. <b>Bootstrap:</b> Registers provider-specific clients as Spring Beans for injection.
 * </p>
 * 
 * <p><b>Behind the Scenes (Infrastructure Handshake):</b>
 * The system utilizes a <b>Back-Channel Token Exchange</b> pattern. After the 
 * frontend completes the front-channel OAuth2 dance, this component provides the 
 * necessary tools for the server to securely "reach back" to the IdP to verify 
 * identity and fetch supplemental user metadata. This establishes a <b>Trust 
 * Handshake</b> between the {@link com.substring.authapp.security.provider.GithubService} 
 * and GitHub's resource servers, ensuring that the <b>Just-In-Time (JIT) 
 * Provisioning</b> logic has the necessary data to synchronize external 
 * identities with the local persistence layer.</p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * By isolating external API configuration here, we ensure that the 
 * {@link com.substring.authapp.security.provider.GithubService} remains focused on 
 * data parsing logic while the "Plumbing" (URLs, Headers, Versioning) is 
 * managed centrally. This promotes <b>DRY (Don't Repeat Yourself)</b> and 
 * simplifies maintenance when external APIs update their versioning schemes.
 * </p>
 */
@Configuration
public class ProviderConfig {

    // ===================================================================================
    // SECTION 1: Social Provider Clients (OAuth2 Support)
    // ===================================================================================

    /**
     * <h1>GitHub API Authorization Engine</h1>
     * 
     * <p>Configures a {@link RestClient} specialized for the GitHub ecosystem.</p>
     * 
     * <p><b>Behind the Scenes (Protocol Handshake):</b>
     * This bean establishes the <b>Trust Relationship</b> between the application 
     * and GitHub's resource servers. It enforces the use of the 2022-11-28 API 
     * version and sets a custom User-Agent to comply with GitHub's anti-abuse policies. 
     * This client is utilized during the {@code fetchAttributes} phase of the 
     * {@link com.substring.authapp.security.OAuth2SuccessHandler}, enabling 
     * a secure <b>Metadata Handshake</b> to retrieve private user emails 
     * facilitating JIT user creation.</p>
     * 
     * @param restClientBuilder The base Spring builder for REST clients.
     * @return A pre-configured client with GitHub's mandatory security headers.
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
