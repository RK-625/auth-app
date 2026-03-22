package com.substring.authapp.security.provider;

import com.substring.authapp.exceptions.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;
import java.util.Optional;


@Service
@RequiredArgsConstructor
public class GithubService {

    private final RestClient restClient;

    // get the Email address from github
    public String getEmailFromGithub(OAuth2AuthorizedClient client) {
        List<Map<String, Object>> emailList = restClient.get()
                .uri("user/emails")
                .headers(h-> h.setBearerAuth(client.getAccessToken().getTokenValue()))
                .retrieve()
                .onStatus(HttpStatusCode::isError,((request, response) -> {
                    throw new BadCredentialsException("GitHub Api Error with code : " + response.getStatusCode());
                }))
                .body(new ParameterizedTypeReference<List<Map<String, Object>>>(){});
        return Optional.of(emailList).orElseThrow(()-> new ResourceNotFoundException("User not found in GitHub Api"))
                .stream()
                .filter(email -> Boolean.TRUE.equals(email.get("primary")))
                .map(email -> (String) email.get("email"))
                .findAny().orElseThrow(() -> new BadCredentialsException("No primary email found in GitHub Api"));
    }
}
