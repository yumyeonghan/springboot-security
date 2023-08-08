package com.example.ssec.config;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
public class WebSecurityConfigure {

    private final Logger log = LoggerFactory.getLogger(getClass());

//    //Spring Mvc Async Request 없이, 별도의 스레드에서 SecurityContextHolder를 통해 SecurityContext를 얻을 수 있게 설정(권장 x)
//    public WebSecurityConfigure() {
//        //MODE_INHERITABLETHREADLOCAL 설정은 기본값인 MODE_THREADLOCAL와 다르게 부모 쓰레드의 변수를 자식 쓰레드도 참조할 수 있게 허용
//        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
//    }

    //ignoring()를 설정하지 않으면 CsrfFilter에 의해 /h2-console 페이지가 막힘
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer () {
        return (web -> web.ignoring().requestMatchers(new AntPathRequestMatcher("/h2-console/**")));
    }

    @Bean
    @Qualifier("myAsyncTaskExecutor")
    public ThreadPoolTaskExecutor threadPoolTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setThreadNamePrefix("my-executor-");
        return executor;
    }

    @Bean
    public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(@Qualifier("myAsyncTaskExecutor") AsyncTaskExecutor delegate) {
        return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
    }

//    //인메모리가 아닌, 데이터베이스를 연동해서 사용자 인증을 처리하려면 다른 구현체(JdbcDaoImpl)를 사용해야함
//    @Bean
//    public InMemoryUserDetailsManager userDetailsManager() {
//        UserDetails admin = makeUserDetails("admin", "1234", "ADMIN");
//        UserDetails user = makeUserDetails("user", "1234", "USER");
//        return new InMemoryUserDetailsManager(user, admin);
//    }

//    private UserDetails makeUserDetails(String name, String password, String role) {
//        return User.withUsername(name)
//                .password(String.format("{noop}%s", password))
//                .roles(role)
//                .build();
//    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
        jdbcDao.setDataSource(dataSource);
        return jdbcDao;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(new AntPathRequestMatcher("/me")).hasAnyRole("USER", "ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/admin")).hasRole("ADMIN")
                        .requestMatchers(new AntPathRequestMatcher("/admin")).fullyAuthenticated()
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
