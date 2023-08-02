package com.example.ssec.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfigure {

    @Bean
    public InMemoryUserDetailsManager userDetailsManager() {
        UserDetails admin = makeUserDetails("admin", "1234", "ADMIN");
        UserDetails user = makeUserDetails("user", "1234", "USER");
        return new InMemoryUserDetailsManager(user, admin);
    }

    private UserDetails makeUserDetails(String name, String password, String role) {
        return User.withUsername(name)
                .password(String.format("{noop}%s", password))
                .roles(role)
                .build();
    }

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
