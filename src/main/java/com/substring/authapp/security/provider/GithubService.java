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
 * Service to handle GitHub-specific external API calls.
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
