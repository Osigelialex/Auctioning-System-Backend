package com.example.biddingsystem.config;

import com.example.biddingsystem.security.AuthenticationPoint;
import com.example.biddingsystem.security.JwtAuthenticationFilter;
import com.example.biddingsystem.security.UserDetailsServiceImpl;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Controller
@EnableWebSecurity
@AllArgsConstructor
@SecurityScheme(
        name = "Bearer Authentication",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        scheme = "bearer"
)
public class SecurityConfig {

    private UserDetailsServiceImpl userDetailsServiceImpl;
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    private AuthenticationPoint authenticationPoint;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req->req
                        .requestMatchers(HttpMethod.GET, "/ping").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/signup").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/products/unprotected").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/products").hasAuthority("SELLER")
                        .requestMatchers(HttpMethod.GET, "/api/v1/products").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/products/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/categories").permitAll()
                        .requestMatchers(HttpMethod.PUT, "/api/v1/products/**").hasAuthority("SELLER")
                        .requestMatchers(HttpMethod.PATCH, "/api/v1/products/approve/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/api/v1/products/reject/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/v1/products/unapproved").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/categories").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/api/v1/categories/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/categories/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/v1/users").hasAuthority("ADMIN")
                        .requestMatchers("/api/v1/dashboard").hasAuthority("ADMIN")
                        .requestMatchers("/api/v1/bids/all").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/bids/place/**").hasAuthority("BUYER") // Fixed path pattern
                        .requestMatchers(HttpMethod.GET, "/api/v1/bids/list/**").permitAll()
                        .requestMatchers(HttpMethod.PATCH, "/api/v1/bids/close/**")
                        .hasAnyAuthority("SELLER", "ADMIN")
                        .requestMatchers("/api/v1/bids/winner/**").hasAuthority("SELLER")
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/notifications/**")
                        .hasAnyAuthority("ADMIN", "SELLER", "BUYER")
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/products/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/transactions").hasAuthority("BUYER")
                        .requestMatchers(HttpMethod.GET, "/api/v1/transactions").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/sendmail/contact").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/verify").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/resend").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/reviews")
                        .hasAnyAuthority("SELLER", "BUYER")
                        .requestMatchers(HttpMethod.GET, "/api/v1/reviews").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/paystack/**").permitAll()
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        .anyRequest().authenticated()
                )
                .userDetailsService(userDetailsServiceImpl)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationPoint))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class).build();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(@NonNull CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
                        .allowedOrigins("https://bidzbuddy.vercel.app", "http://127.0.0.1:5173")
                        .allowedHeaders("*")
                        .allowCredentials(true);
            }
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}