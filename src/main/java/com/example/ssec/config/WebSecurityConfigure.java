package com.example.ssec.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfigure {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/me").hasAnyRole("USER", "ADMIN")
                        .anyRequest().permitAll())
                .formLogin(auth -> auth.defaultSuccessUrl("/")
                        .permitAll())
                .build();
    }
}
