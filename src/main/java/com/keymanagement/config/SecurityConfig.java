package com.keymanagement.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
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
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

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
     */
    // Disabled under "integration-test" so those tests can supply their own permissive
    // SecurityFilterChain without two chains both matching "any request".
    @Bean
    @Profile("!integration-test")
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        PathPatternRequestMatcher.Builder paths = PathPatternRequestMatcher.withDefaults();
        RequestMatcher bearerApiRequest = new AndRequestMatcher(paths.matcher("/api/keys/**"), request -> {
            String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
            return authorization != null && authorization.startsWith("Bearer ")
                    && StringUtils.hasText(authorization.substring(7));
        });
        RequestMatcher jsonAuthenticationRequest = new AndRequestMatcher(
                new OrRequestMatcher(paths.matcher(HttpMethod.POST, "/api/auth/login"),
                        paths.matcher(HttpMethod.POST, "/api/auth/register")),
                request -> {
                    String contentType = request.getContentType();
                    if (contentType == null) {
                        return false;
                    }
                    try {
                        MediaType mediaType = MediaType.parseMediaType(contentType);
                        return MediaType.APPLICATION_JSON.includes(mediaType)
                                || new MediaType("application", "*+json").includes(mediaType);
                    } catch (InvalidMediaTypeException exception) {
                        return false;
                    }
                });

        http
                .csrf(csrf -> csrf.ignoringRequestMatchers(bearerApiRequest, jsonAuthenticationRequest))
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
