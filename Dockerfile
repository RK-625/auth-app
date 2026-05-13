# =============================================================================
# Multi-Stage Dockerfile for High-Security Spring Boot Backend
# =============================================================================

# --- STAGE 1: Builder (Maven Cache Optimization) ---
FROM maven:3.9.9-eclipse-temurin-21-alpine AS builder
WORKDIR /build

# Copy only the POM first to cache dependencies in a dedicated Docker layer
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build the shaded JAR
COPY src ./src
RUN mvn clean package -DskipTests

# --- STAGE 2: Runtime (Minimal Alpine JRE) ---
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Security Hardening: Create a non-root user to run the application
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Copy the compiled JAR from the builder stage
COPY --from=builder /build/target/*.jar app.jar

# Application Configuration
EXPOSE 8082

# JVM Performance Tuning for Containers
# - Use 'cgroup' limits to prevent OOM kills
# - Optimize heap for container resources
ENTRYPOINT ["java", \
            "-XX:+UseContainerSupport", \
            "-XX:MaxRAMPercentage=75.0", \
            "-Djava.security.egd=file:/dev/./urandom", \
            "-jar", "app.jar"]
