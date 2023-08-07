package com.example.ssec.config;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class WebSecurityConfigure {

    private final Logger log = LoggerFactory.getLogger(getClass());

    //Spring Mvc Async Request 없이, 별도의 스레드에서 SecurityContextHolder를 통해 SecurityContext를 얻을 수 있게 설정
    public WebSecurityConfigure() {
        //MODE_INHERITABLETHREADLOCAL 설정은 기본값인 MODE_THREADLOCAL와 다르게 부모 쓰레드의 변수를 자식 쓰레드도 참조할 수 있게 허용
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

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
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/admin").fullyAuthenticated()
                        .anyRequest().permitAll())
                .formLogin(auth -> auth
                        .defaultSuccessUrl("/")
                        //.loginPage("/my-login") 직접 로그인 페이지 사용할 경우 설정
                        .usernameParameter("my-username")
                        .passwordParameter("my-password")
                        .permitAll())
                .logout(auth -> auth
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true))
                .rememberMe(auth -> auth
                        .key("my-remember-me")
                        .rememberMeParameter("remember-me")
                        .tokenValiditySeconds(300))
                .requiresChannel(auth -> auth
                        .anyRequest().requiresSecure())
                .anonymous(auth -> auth
                        .principal("thisIsAnonymousUser")
                        .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN"))
                .exceptionHandling(auth -> auth
                        .accessDeniedHandler(accessDeniedHandler()))
                .sessionManagement(auth -> auth
                        .sessionFixation().changeSessionId()
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .invalidSessionUrl("/")
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false))
                .build();
    }

    //Custom AccessDeniedHandler
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }
}
