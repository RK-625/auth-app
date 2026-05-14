package com.substring.authapp.security.provider;

import com.substring.authapp.exceptions.ResourceNotFoundException;
import com.substring.authapp.helpers.MessageHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;

@ExtendWith(MockitoExtension.class)
class GithubServiceTest {

    @Mock
    private MessageHelper messageHelper;

    private GithubService githubService;
    private MockRestServiceServer mockServer;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(builder).build();
        RestClient restClient = builder.build();
        githubService = new GithubService(restClient, messageHelper);
    }

    @Test
    void getEmailFromGithub_WithValidPrimaryEmail_ReturnsEmail() {
        OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
        OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
        when(client.getAccessToken()).thenReturn(accessToken);
        when(accessToken.getTokenValue()).thenReturn("mock-github-token");

        String mockJsonResponse = """
                [
                    {"email": "secondary@test.com", "primary": false},
                    {"email": "primary@test.com", "primary": true}
                ]
                """;

        mockServer.expect(requestTo("user/emails"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer mock-github-token"))
                .andRespond(withSuccess(mockJsonResponse, MediaType.APPLICATION_JSON));

        String email = githubService.getEmailFromGithub(client);

        assertThat(email).isEqualTo("primary@test.com");
        mockServer.verify();
    }

    @Test
    void getEmailFromGithub_WithoutPrimaryEmail_ThrowsBadCredentialsException() {
        OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
        OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
        when(client.getAccessToken()).thenReturn(accessToken);
        when(accessToken.getTokenValue()).thenReturn("mock-github-token");

        String mockJsonResponse = """
                [
                    {"email": "secondary@test.com", "primary": false}
                ]
                """;

        mockServer.expect(requestTo("user/emails"))
                .andRespond(withSuccess(mockJsonResponse, MediaType.APPLICATION_JSON));

        when(messageHelper.getMessage(eq("external.github.error"), anyString())).thenReturn("No primary email found");

        assertThatThrownBy(() -> githubService.getEmailFromGithub(client))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("No primary email found");

        mockServer.verify();
    }

    @Test
    void getEmailFromGithub_WhenApiFails_ThrowsBadCredentialsException() {
        OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
        OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
        when(client.getAccessToken()).thenReturn(accessToken);
        when(accessToken.getTokenValue()).thenReturn("mock-github-token");

        mockServer.expect(requestTo("user/emails"))
                .andRespond(withServerError());

        when(messageHelper.getMessage(eq("external.github.error"), any())).thenReturn("Server Error");

        assertThatThrownBy(() -> githubService.getEmailFromGithub(client))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Server Error");

        mockServer.verify();
    }
}
