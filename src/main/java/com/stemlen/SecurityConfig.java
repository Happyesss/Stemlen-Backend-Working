package com.stemlen;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;

import com.stemlen.jwt.JwtAuthEntryPoint;
import com.stemlen.jwt.JwtAuthFilter;
import com.stemlen.jwt.OAuth2SuccessHandler;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private JwtAuthEntryPoint point;

    @Autowired
    private JwtAuthFilter filter;

    @Autowired
    private OAuth2SuccessHandler oauth2SuccessHandler; // Inject the OAuth2 success handler

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Enable CORS
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/auth/login", 
                    "/users/register", 
                    "/users/changepassword",
                    "/users/verifyOtp/**", 
                    "/users/sendOtp/**",
                    "/oauth2/**" 
                ).permitAll()
                .requestMatchers("/jobs/getAll", "/hackathons/getAll").permitAll() // Public access
                .anyRequest().authenticated()
            )
            .exceptionHandling(ex -> ex.authenticationEntryPoint(point))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .oauth2Login(oauth2 -> oauth2 // Enable OAuth2 login
                .successHandler(oauth2SuccessHandler) // Use the custom OAuth2 success handler
            );

        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("https://www.stemlen.com")); // Allow origin
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

//package com.stemlen;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//import com.stemlen.jwt.JwtAuthEntryPoint;
//import com.stemlen.jwt.JwtAuthFilter;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//	
//	@Autowired
//	private JwtAuthEntryPoint point;
//	
//	@Autowired
//	private JwtAuthFilter filter;
//
//   
//
//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//	    http.csrf(csrf -> csrf.disable())
//	        .authorizeRequests()
//	        .requestMatchers("/auth/login", "/users/register", "/users/verifyOtp/**", "/users/sendOtp/**").permitAll() // Fix: Added "/" before "users/register"
//	        .anyRequest()
//	        .authenticated()
//	        .and()
//	        .exceptionHandling(ex -> ex.authenticationEntryPoint(point))
//	        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//	    
//	    http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
//	    return http.build();
//	}
//
//}
