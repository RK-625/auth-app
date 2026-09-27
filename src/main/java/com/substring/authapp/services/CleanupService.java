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
 * <h1>Background Maintenance & "Garbage Collection" Engine</h1>
 * 
 * <p>Handles autonomous maintenance tasks to ensure database performance and 
 * data integrity. It acts as the system's <b>Garbage Collector</b> for 
 * temporary security handshake objects (OTPs, Sign-up Handshakes, Password Resets).</p>
 * 
 * <p><b>The Garbage Collection Pattern:</b>
 * This service implements a proactive data sanitization strategy. Instead of 
 * leaving expired records to accumulate and bloat indexes, it "sweeps" the 
 * staging tables every 15 minutes. This prevents performance degradation in 
 * the {@link SignUpObjectRepository} and {@link ResetPasswordObjectRepository} 
 * by ensuring that table scans (even on indexed columns) remain lightning-fast.</p>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>Trigger:</b> Executes on a recurring schedule defined by the 
 *    {@link Scheduled} CRON expression every 15 minutes.
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
     * 1. <b>Schedule:</b> Triggered every 15 minutes ({@code 0 0/15 * * * *}).
     * 2. <b>Batch Deletion Logic:</b> Rather than deleting records one-by-one, 
     *    the service issues a single <b>Batch Deletion</b> query ({@code deleteByExpiresAtBefore}) 
     *    per entity type. This minimizes network round-trips to the database and 
     *    reduces transaction log pressure.
     * 3. <b>Persistence Guard:</b> The {@link Transactional} annotation ensures 
     *    that the entire batch operation is atomic.
     * </p>
     * 
     * <p><b>Design Rationale:</b>
     * 15-minute purging ensures that expired handshakes (typically 5-min TTL) 
     * are cleared aggressively. The use of batch deletes ensures that even under 
     * high load, the maintenance window remains brief and non-intrusive.</p>
     */
    @Scheduled(cron = "0 0/15 * * * *") // Runs every 15 minutes
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
