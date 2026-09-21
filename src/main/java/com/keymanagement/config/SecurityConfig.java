package com.keymanagement.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.keymanagement.security.CustomUserDetailsService;
import com.keymanagement.security.JwtAuthenticationFilter;

/**
 * Security configuration for the KMS application.
 * Configures JWT-based authentication and authorization.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(CustomUserDetailsService customUserDetailsService,
                         JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.customUserDetailsService = customUserDetailsService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    /**
     * Configure HTTP security.
     * 
     * CSRF Protection Disabled - Justification:
     * This is a stateless REST API using JWT token-based authentication.
     * CSRF protection is NOT required because:
     * 1. SessionCreationPolicy.STATELESS - No server-side sessions or cookies
     * 2. JWT tokens are sent via Authorization header, not cookies
     * 3. Browsers do not automatically attach Authorization headers to requests
     * 4. CSRF attacks rely on browsers automatically sending cookies with requests
     * 5. This API is designed for non-browser clients (mobile apps, services)
     * 
     * Reference: Spring Security docs state CSRF protection is only needed when
     * "processing requests from browser clients" using cookie-based authentication.
     * https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html
     * 
     * Note: the corresponding CodeQL alert (java/spring-disabled-csrf-protection) must be
     * dismissed manually in the GitHub Security tab - "lgtm[rule-id]" suppression comments
     * are a legacy lgtm.com convention and are not honored by GitHub's default CodeQL setup.
     */
    // Disabled under "integration-test" so those tests can supply their own permissive
    // SecurityFilterChain without two chains both matching "any request".
    @Bean
    @Profile("!integration-test")
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF disabled - safe for stateless JWT authentication (see method javadoc)
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(authz -> authz
                        // Public endpoints
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        
                        // API endpoints require authentication
                        .requestMatchers("/api/keys/**").authenticated()
                        
                        // All other requests require authentication
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Configure authentication provider.
     * Using constructor injection to avoid deprecated setUserDetailsService method.
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Configure password encoder (BCrypt).
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Expose authentication manager bean.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
