package com.substring.authapp.services;


import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <h1>IP-Based Rate Limiting Engine</h1>
 * 
 * <p>Manages the stateful tracking of API request limits per client IP address. 
 * This service implements the <b>Token Bucket Algorithm</b> to protect sensitive 
 * endpoints (like login and signup) from Brute Force and DDoS attacks.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Lookup:</b> Receives an IP address and checks the in-memory cache.
 * 2. <b>Provisioning:</b> If the IP is unseen, provisions a new {@link Bucket}.
 * 3. <b>Retrieval:</b> Returns the specific {@link Bucket} instance for request consumption.</p>
 * 
 * <p><b>Behind the Scenes (Concurrency & Memory):</b>
 * Utilizes a {@link ConcurrentHashMap} to ensure thread-safe operations across 
 * thousands of simultaneous requests without the performance penalty of synchronized 
 * blocks. The {@link Map#computeIfAbsent} guarantees atomic bucket creation.</p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * In-memory rate limiting is prioritized over database/Redis tracking for the 
 * authentication layer to ensure zero-latency blocking of malicious traffic. 
 * The bucket is configured to allow a burst of 10 requests, refilling completely 
 * every 60 seconds, balancing strict security with a forgiving user experience.</p>
 */
@Service
public class RateLimiterService {

    // ===================================================================================
    // SECTION 1: Infrastructure & Cache (Fields)
    // ===================================================================================

    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();

    // ===================================================================================
    // SECTION 2: Rate Limiting Logic (Public)
    // ===================================================================================

    /**
     * Resolves the token bucket associated with a specific IP address.
     * 
     * @param ipAddress The client's IPv4/IPv6 address.
     * @return The {@link Bucket} for the given IP.
     */
    public Bucket resolveBucket(String ipAddress){
        return cache.computeIfAbsent(ipAddress, this::newBucket);
    }

    // ===================================================================================
    // SECTION 3: Provisioning Engine (Internal)
    // ===================================================================================

    /**
     * Factory method to create a fresh token bucket for a new IP.
     */
    private Bucket newBucket(String ipAddress){
        Refill refill = Refill.intervally(10, Duration.ofMinutes(1));
        Bandwidth limit = Bandwidth.classic(10,refill);
        return Bucket.builder().addLimit(limit).build();
    }
}
