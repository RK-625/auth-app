package com.substring.authapp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.authapp.dtos.ApiError;
import com.substring.authapp.entities.User;
import com.substring.authapp.security.JwtAuthenticationFilter;
import com.substring.authapp.security.OAuth2SuccessHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Map;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {


    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(authorizeHttpRequests ->
                authorizeHttpRequests.requestMatchers("/api/v1/auth/register").permitAll()
                        .requestMatchers("/api/v1/auth/login").permitAll()
                        .requestMatchers("/login/oauth2/**").permitAll()
                        .requestMatchers("/oauth2/**","/login", "/login/**").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/v1/auth/refresh").permitAll()
                        .requestMatchers("/api/v1/auth/logout").permitAll()
                        .anyRequest().authenticated()
                ).oauth2Login(oauth2 -> oauth2.successHandler(authenticationSuccessHandler).failureHandler((req, res, ex) -> {
                    log.error("OAuth2 failure URI: {}", req.getRequestURI());
                    log.error("Query: {}", req.getQueryString());
                    log.error("Full URL: {}", req.getRequestURL());
                    log.error("Exception: {}", ex.getMessage(), ex);
                    res.sendRedirect("/api/v1/auth/oauth2/failure");
                })).logout(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(e -> e.authenticationEntryPoint((req, rsp, e1) -> {
                    e1.printStackTrace();
                    rsp.setStatus(401);
                    rsp.setContentType("application/json");
                    String error =(String) req.getAttribute("error");
                    log.error("Error is : {}",error);
                    String message = "Unauthorized access " + e1.getMessage();
                    if(error != null) message = error;
                    var apierror = ApiError.of(rsp.getStatus(), "Unauthorized", message, req.getRequestURI());
                    rsp.getWriter().write(objectMapper.writeValueAsString(apierror));
                }));
        return http.build();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
