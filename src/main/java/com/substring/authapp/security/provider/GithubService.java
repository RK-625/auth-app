package com.substring.authapp.security.provider;

import org.apache.coyote.Response;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;


@Service
public class GithubService {

    // get the Email address from github
    public String getEmailFromGithub(OAuth2AuthorizedClient client) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(client.getAccessToken().getTokenValue());
        headers.set("User-Agent", "Bat-Security");
        headers.setAccept(List.of(MediaType.parseMediaType("application/vnd.github+json")));
        headers.setCacheControl(CacheControl.noCache());
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try{
            ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange("https://api.github.com/user/emails", HttpMethod.GET, entity, new ParameterizedTypeReference<List<Map<String, Object>>>() {});
            List<Map<String, Object>> emails = response.getBody();
            for (Map<String, Object> email : emails) {
                if ((Boolean) email.get("primary") == true) {
                    String s = (String) email.get("email");
                    return s;
                }
            }
        }catch (Exception e){
            throw new BadCredentialsException("The email is present in the Github");
        }
        return null;
    }
}
