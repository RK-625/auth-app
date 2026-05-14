package com.substring.authapp.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.common.ApiError;
import com.substring.authapp.helpers.MessageHelper;
import com.substring.authapp.services.RateLimiterService;
import io.github.bucket4j.Bucket;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitingFilterTest {

    @Mock
    private RateLimiterService rateLimiterService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private MessageHelper messageHelper;

    @Mock
    private MeterRegistry meterRegistry;

    @Mock
    private FilterChain filterChain;

    @Mock
    private Bucket bucket;

    @Mock
    private Counter counter;

    @InjectMocks
    private RateLimitingFilter rateLimitingFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    void doFilterInternal_WithTokensAvailable_ContinuesChain() throws Exception {
        request.setRequestURI("/api/v1/auth/login");
        request.setRemoteAddr("192.168.1.1");
        
        when(rateLimiterService.resolveBucket("192.168.1.1")).thenReturn(bucket);
        when(bucket.tryConsume(1)).thenReturn(true);

        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WithoutTokens_ReturnsTooManyRequests() throws Exception {
        request.setRequestURI("/api/v1/auth/login");
        request.setRemoteAddr("192.168.1.1");

        when(rateLimiterService.resolveBucket("192.168.1.1")).thenReturn(bucket);
        when(bucket.tryConsume(1)).thenReturn(false);
        when(meterRegistry.counter("auth.rate.limit.blocked")).thenReturn(counter);
        when(messageHelper.getMessage("system.error.too_many_requests")).thenReturn("Too many requests.");
        when(objectMapper.writeValueAsString(any(ApiError.class))).thenReturn("{\"message\":\"Too many requests.\"}");

        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS.value());
        verify(counter).increment();
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void getClientIp_ParsesXForwardedForCorrectly() throws Exception {
        request.setRequestURI("/api/v1/auth/login");
        request.addHeader("X-Forwarded-For", "10.0.0.1, 192.168.0.2");
        request.setRemoteAddr("192.168.0.3");

        when(rateLimiterService.resolveBucket("10.0.0.1")).thenReturn(bucket);
        when(bucket.tryConsume(1)).thenReturn(true);

        rateLimitingFilter.doFilterInternal(request, response, filterChain);

        verify(rateLimiterService).resolveBucket("10.0.0.1");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotFilter_NonAuthEndpoints_AreBypassed() {
        request.setRequestURI("/api/v1/users/profile");
        boolean result = rateLimitingFilter.shouldNotFilter(request);
        assertThat(result).isTrue();
    }

    @Test
    void shouldNotFilter_AuthRefresh_IsBypassed() {
        request.setRequestURI("/api/v1/auth/refresh");
        boolean result = rateLimitingFilter.shouldNotFilter(request);
        assertThat(result).isTrue();
    }

    @Test
    void shouldNotFilter_AuthLogout_IsBypassed() {
        request.setRequestURI("/api/v1/auth/logout");
        boolean result = rateLimitingFilter.shouldNotFilter(request);
        assertThat(result).isTrue();
    }
}
