package com.substring.authapp.services;

import io.github.bucket4j.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimiterServiceTest {

    private RateLimiterService rateLimiterService;

    @BeforeEach
    void setUp() {
        rateLimiterService = new RateLimiterService();
    }

    @Test
    void resolveBucket_ShouldReturnSameBucketForSameIp() {
        String ip = "192.168.1.1";
        
        Bucket bucket1 = rateLimiterService.resolveBucket(ip);
        Bucket bucket2 = rateLimiterService.resolveBucket(ip);
        
        assertThat(bucket1).isSameAs(bucket2);
    }

    @Test
    void resolveBucket_ShouldReturnDifferentBucketsForDifferentIps() {
        Bucket bucket1 = rateLimiterService.resolveBucket("1.1.1.1");
        Bucket bucket2 = rateLimiterService.resolveBucket("2.2.2.2");
        
        assertThat(bucket1).isNotSameAs(bucket2);
    }

    @Test
    void resolveBucket_ShouldInitializeWithCorrectCapacity() {
        Bucket bucket = rateLimiterService.resolveBucket("127.0.0.1");
        
        assertThat(bucket.getAvailableTokens()).isEqualTo(10);
    }
}
