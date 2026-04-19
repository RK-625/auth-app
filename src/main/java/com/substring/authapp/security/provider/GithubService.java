package com.substring.authapp.security.provider;

import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.MessageHelper;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * <h1>GitHub OAuth2 Integration Service</h1>
 *
 * <p>Handles external API interactions with GitHub, specifically retrieving user profile 
 * data that is not provided in the initial OAuth2 payload.</p>
 *
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Authentication:</b> Receives the {@link org.springframework.security.oauth2.client.OAuth2AuthorizedClient} containing the GitHub access token.
 * 2. <b>API Call:</b> Uses {@link org.springframework.web.client.RestClient} to query the GitHub REST API securely.
 * 3. <b>Extraction:</b> Parses the JSON response to extract specific claims (e.g., the primary email).
 * </p>
 *
 * <p><b>Behind the Scenes (Component Interaction):</b>
 * This service acts as an extension of the {@link com.substring.authapp.security.OAuth2SuccessHandler}. Because GitHub does not always include the user's email in the primary {@code user-info-uri} response (especially if the email is private), this service makes a secondary, authenticated request to the {@code /user/emails} endpoint to guarantee we can uniquely identify the user in our system.
 * </p>
 *
 * <p><b>Design Rationale (The "Why"):</b>
 * Encapsulating external API calls behind a specific service isolates the core authentication logic from third-party API changes. It also ensures that all requests to GitHub use the central, pre-configured {@link RestClient}.
 * </p>
 */
@Service
public class GithubService {

    private final RestClient restClient;
    private final MessageHelper messageHelper;

    public GithubService(RestClient restClient, MessageHelper messageHelper) {
        this.restClient = restClient;
        this.messageHelper = messageHelper;
    }

    /**
     * Fetches the primary email address from GitHub for the authenticated user.
     *
     * <p><b>Implementation Workflow:</b>
     * 1. Constructs an HTTP GET request to {@code user/emails}.
     * 2. Injects the GitHub Bearer token into the authorization header.
     * 3. Filters the response list to find the email object marked as {@code primary}.
     * </p>
     *
     * <p><b>Behind the Scenes:</b>
     * If the API call fails or no primary email is found, this method throws a {@link BadCredentialsException} 
     * or {@link ResourceNotFoundException}. These exceptions halt the OAuth2 flow and are caught by the 
     * global exception handler, preventing the creation of an orphaned user account without an email.
     * </p>
     *
     * @param client The authorized client containing the valid GitHub access token.
     * @return The verified primary email string.
     * @throws BadCredentialsException If the API call fails or no primary email is found.
     */
    public String getEmailFromGithub(OAuth2AuthorizedClient client) {
        List<Map<String, Object>> emailList = restClient.get()
                .uri("user/emails")
                .headers(h -> h.setBearerAuth(client.getAccessToken().getTokenValue()))
                .retrieve()
                .onStatus(HttpStatusCode::isError, (request, response) -> {
                    throw new BadCredentialsException(messageHelper.getMessage("external.github.error", response.getStatusCode()));
                })
                .body(new ParameterizedTypeReference<List<Map<String, Object>>>() {});

        return Optional.ofNullable(emailList)
                .orElseThrow(() -> new ResourceNotFoundException(messageHelper.getMessage("external.github.error", "User not found")))
                .stream()
                .filter(email -> Boolean.TRUE.equals(email.get("primary")))
                .map(email -> (String) email.get("email"))
                .findAny()
                .orElseThrow(() -> new BadCredentialsException(messageHelper.getMessage("external.github.error", "No primary email found")));
    }


}
