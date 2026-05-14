package com.substring.authapp.security;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CookieServiceTest {

    private CookieService cookieService;
    private final String refreshTokenName = "refresh_token";
    private final String domain = "localhost";
    private final String sameSite = "Lax";

    @BeforeEach
    void setUp() {
        cookieService = new CookieService(
                refreshTokenName,
                true,   // httpOnly
                true,   // secure
                domain,
                sameSite
        );
    }

    @Test
    void attachRefreshCookie_ShouldSetSecurityAttributesAndHint() {
        HttpServletResponse response = mock(HttpServletResponse.class);
        String token = "mock-jwt-token";
        int maxAge = 3600;

        cookieService.attachRefreshCookie(response, token, maxAge);

        ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
        verify(response, times(2)).addHeader(eq(HttpHeaders.SET_COOKIE), headerCaptor.capture());

        List<String> cookies = headerCaptor.getAllValues();
        
        // Check Refresh Token Cookie
        String refreshCookie = cookies.stream()
                .filter(c -> c.startsWith(refreshTokenName))
                .findFirst()
                .orElseThrow();
        
        assertThat(refreshCookie).contains(token);
        assertThat(refreshCookie).contains("HttpOnly");
        assertThat(refreshCookie).contains("Secure");
        assertThat(refreshCookie).contains("Max-Age=" + maxAge);
        assertThat(refreshCookie).contains("SameSite=" + sameSite);
        assertThat(refreshCookie).contains("Domain=" + domain);

        // Check Logged In Hint
        String hintCookie = cookies.stream()
                .filter(c -> c.startsWith("logged_in"))
                .findFirst()
                .orElseThrow();
        
        assertThat(hintCookie).contains("true");
        assertThat(hintCookie).doesNotContain("HttpOnly");
        assertThat(hintCookie).contains("Secure");
    }

    @Test
    void clearRefreshCookie_ShouldSetMaxAgeToZero() {
        HttpServletResponse response = mock(HttpServletResponse.class);

        cookieService.clearRefreshCookie(response);

        ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
        verify(response, times(2)).addHeader(eq(HttpHeaders.SET_COOKIE), headerCaptor.capture());

        List<String> cookies = headerCaptor.getAllValues();
        for (String cookie : cookies) {
            assertThat(cookie).contains("Max-Age=0");
        }
    }

    @Test
    void addNoStoreHeadersToResponse_ShouldSetCorrectHeaders() {
        HttpServletResponse response = mock(HttpServletResponse.class);

        cookieService.addNoStoreHeadersToResponse(response);

        verify(response).setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        verify(response).setHeader("Pragma", "no-cache");
    }
}
