package com.substring.authapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * <h1>Authentication Microservice Bootstrapper</h1>
 * 
 * <p>The primary entry point for the Spring Boot application. This class initializes the 
 * Spring {@code ApplicationContext}, performs component scanning, and triggers the 
 * auto-configuration of security, persistence, and web infrastructures.</p>
 * 
 * <h3>Infrastructure Handshakes</h3>
 * <p>The application activates several high-level subsystems during startup to ensure 
 * <b>Operational Resilience</b> and <b>Performance</b>:</p>
 * <ul>
 *   <li><b>Asynchronous Execution Handshake ({@link EnableAsync}):</b> Enables the "Task Executor" system. 
 *       This is critical for offloading high-latency I/O operations, such as SMTP email 
 *       dispatch during registration, to dedicated background threads. This prevents 
 *       thread starvation in the web container.</li>
 *   <li><b>Scheduled Maintenance Handshake ({@link EnableScheduling}):</b> Activates the 
 *       "Task Scheduler" engine. This allows the {@link com.substring.authapp.services.CleanupService} 
 *       to perform autonomous database sanitization, purging expired OTPs and 
 *       stale "Sign-Up Objects" to prevent <b>Data Rot</b>.</li>
 * </ul>
 * 
 * <p><b>Implementation Workflow:</b>
 * 1. <b>JVM Bootstrap:</b> Invokes {@code SpringApplication.run} to launch the Spring container.
 * 2. <b>Component Discovery:</b> Scans the {@code com.substring.authapp} package for Beans.
 * 3. <b>Infrastructure Ignition:</b> Initializes the Hikari Connection Pool, JPA Providers, and Security Filter Chains.
 * 4. <b>Handshake Completion:</b> Begins background maintenance tasks and opens the HTTP port for traffic.</p>
 * 
 * <p><b>Design Rationale (The "Why"):</b>
 * By centralizing these high-level toggles here, we provide a <b>Single Source of Truth</b> 
 * for the application's capability set. This ensures that any developer can understand 
 * the macro-level behavior of the service (e.g., that it supports background tasks 
 * and scheduling) just by glancing at the bootstrapper.</p>
 */
@SpringBootApplication
@EnableAsync
@EnableScheduling
public class AuthAppApplication {

    // ===================================================================================
    // SECTION 1: System Entry Point
    // ===================================================================================

    /**
     * Main method to launch the application.
     * @param args Command-line arguments.
     */
    public static void main(String[] args) {
        SpringApplication.run(AuthAppApplication.class, args);
    }

}