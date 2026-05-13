package com.substring.authapp.services;

import com.substring.authapp.repositories.ResetPasswordObjectRepository;
import com.substring.authapp.repositories.SignUpObjectRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * <h1>Background Maintenance & "Hourly Garbage Collection" Engine</h1>
 * 
 * <p>Handles autonomous maintenance tasks to ensure database performance and 
 * data integrity. It acts as the system's <b>Hourly Garbage Collector</b> for 
 * temporary security handshake objects (OTPs, Sign-up Handshakes, Password Resets).</p>
 * 
 * <p><b>The "Hourly Garbage Collection" Pattern:</b>
 * This service implements a proactive data sanitization strategy. Instead of 
 * leaving expired records to accumulate and bloat indexes, it "sweeps" the 
 * staging tables every 60 minutes. This prevents performance degradation in 
 * the {@link SignUpObjectRepository} and {@link ResetPasswordObjectRepository} 
 * by ensuring that table scans (even on indexed columns) remain lightning-fast.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Trigger:</b> Executes on a recurring schedule defined by the 
 *    {@link Scheduled} CRON expression at the top of every hour.
 * 2. <b>Discovery:</b> Identifies stale records whose TTL has expired relative to {@code Instant.now()}.
 * 3. <b>Batch Deletion:</b> Executes atomic, high-performance batch deletions to reclaim storage.
 * </p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CleanupService {

    // ===================================================================================
    // SECTION 1: Infrastructure (Dependencies)
    // ===================================================================================

    private final SignUpObjectRepository signUpObjectRepository;
    private final ResetPasswordObjectRepository resetPasswordObjectRepository;
    private Instant lastRun;

    public Instant getLastRun() {
        return lastRun;
    }

    // ===================================================================================
    // SECTION 2: Maintenance Tasks (Scheduled)
    // ===================================================================================

    /**
     * <h1>Stale Handshake Purge Task (The Batch Purge)</h1>
     * 
     * <p>Automatically removes abandoned or expired signup and password reset 
     * attempts from the database to keep the staging tables lean.</p>
     * 
     * <p><b>Implementation Workflow:</b>
     * 1. <b>Schedule:</b> Triggered hourly ({@code 0 0 * * * *}).
     * 2. <b>Batch Deletion Logic:</b> Rather than deleting records one-by-one, 
     *    the service issues a single <b>Batch Deletion</b> query ({@code deleteByExpiresAtBefore}) 
     *    per entity type. This minimizes network round-trips to the database and 
     *    reduces transaction log pressure.
     * 3. <b>Persistence Guard:</b> The {@link Transactional} annotation ensures 
     *    that the entire batch operation is atomic.
     * </p>
     * 
     * <p><b>Design Rationale:</b>
     * Hourly purging balances database load with data minimization. The use of 
     * batch deletes ensures that even under high load (thousands of expired 
     * handshakes), the maintenance window remains brief and non-intrusive.</p>
     */
    @Scheduled(cron = "0 0 * * * *") // Runs every hour
    @Transactional
    public void purgeExpiredHandshakes() {
        log.info("Initiating background purge of expired security handshake records...");
        this.lastRun = Instant.now();
        try {
            signUpObjectRepository.deleteByExpiresAtBefore(Instant.now());
            resetPasswordObjectRepository.deleteByExpiresAtBefore(Instant.now());
            log.info("Successfully sanitized signup and reset staging tables.");
        } catch (Exception e) {
            log.error("Cleanup cycle failed: {}", e.getMessage());
        }
    }
}
