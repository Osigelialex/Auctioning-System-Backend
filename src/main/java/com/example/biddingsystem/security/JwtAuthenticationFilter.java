package com.example.biddingsystem.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@AllArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        String method = request.getMethod();
        log.debug("Processing request: {} {}", method, requestURI);

        String token = getTokenFromHeader(request);

        if (!StringUtils.hasText(token)) {
            log.debug("No token found in request headers for: {} {}", method, requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("Token found, validating...");

        try {
            if (jwtService.validateToken(token)) {
                log.debug("Token is valid, extracting username...");
                String username = jwtService.extractUsername(token);
                log.debug("Username extracted: {}", username);

                // Load associated user from database
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                log.debug("User details loaded for username: {}, authorities: {}",
                        username, userDetails.getAuthorities());

                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                log.debug("Authentication successful for user: {}", username);
            } else {
                log.warn("Token validation failed for request: {} {}", method, requestURI);
            }
        } catch (Exception e) {
            log.error("Error during JWT authentication for request: {} {}", method, requestURI, e);
        }

        filterChain.doFilter(request, response);
    }

    public String getTokenFromHeader(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        log.debug("Authorization header: {}", authHeader != null ? "Bearer ***" : "null");

        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}