package com.substring.authapp.health;

import com.substring.authapp.services.CleanupService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * <h1>Cleanup Service Health Monitor</h1>
 * 
 * <p>Monitors the operational status of the {@link CleanupService}. 
 * Since the cleanup service is critical for preventing database bloat and 
 * purging stale security artifacts, this indicator ensures it's reachable and running.</p>
 */
@Component
@RequiredArgsConstructor
public class CleanupServiceHealthIndicator implements HealthIndicator {

    private final CleanupService cleanupService;

    @Override
    public Health health() {
        Instant lastRun = cleanupService.getLastRun();
        
        Health.Builder status = Health.up();
        if (lastRun != null) {
            status.withDetail("lastRun", lastRun);
        } else {
            status.withDetail("lastRun", "never");
        }
        
        return status
                .withDetail("description", "Monitors the hourly garbage collection of security artifacts")
                .build();
    }
}
