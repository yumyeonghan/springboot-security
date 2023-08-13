package com.example.ssec.config;

import com.example.ssec.jwt.Jwt;
import com.example.ssec.jwt.JwtAuthenticationFilter;
import com.example.ssec.oauth2.OAuth2AuthenticationSuccessHandler;
import com.example.ssec.user.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class WebSecurityConfigure {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final UserService userService;
    private final JwtConfigure jwtConfigure;
    //private final DataSource dataSource;

    public WebSecurityConfigure(UserService userService, JwtConfigure jwtConfigure) {
        this.userService = userService;
        this.jwtConfigure = jwtConfigure;
    }

    @Bean
    public Jwt jwt() {
        return new Jwt(
                jwtConfigure.getIssuer(),
                jwtConfigure.getClientSecret(),
                jwtConfigure.getExpirySeconds()
        );
    }

    //DelegatingPasswordEncoder를 사용하려면,
    //DB에 '$2a$10$B32L76wyCEGqG/UVKPYk9uqZHCWb7k4ci98VTQ7l.dCEib/kzpKGe' 대신, '{bcrypt}$2a$10$B32L76wyCEGqG/UVKPYk9uqZHCWb7k4ci98VTQ7l.dCEib/kzpKGe' 데이터를 삽입
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

//    //UserService 사용하기 위해 삭제
//    @Bean
//    public JdbcUserDetailsManager jdbcUserDetailsManager() {
//        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//        jdbcUserDetailsManager.setUsersByUsernameQuery("SELECT " +
//                "login_id, passwd, true " +
//                "FROM " +
//                "users " +
//                "WHERE " +
//                "login_id = ?");
//        jdbcUserDetailsManager.setGroupAuthoritiesByUsernameQuery( "SELECT " +
//                "u.login_id, g.name, p.name " +
//                "FROM " +
//                "users u JOIN groups g ON u.group_id = g.id " +
//                "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
//                "JOIN permissions p ON p.id = gp.permission_id " +
//                "WHERE " +
//                "u.login_id = ?");
//        jdbcUserDetailsManager.setEnableAuthorities(false);
//        jdbcUserDetailsManager.setEnableGroups(true);
//        return jdbcUserDetailsManager;
//    }

//    //이건 권장하지 않는 방법임
//    //remember-me 옵션을 주고, 로그인을 하면 IllegalStateException("UserDetailsService is required") 발생
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
//        jdbcDao.setDataSource(dataSource);
//        jdbcDao.setEnableAuthorities(false);
//        jdbcDao.setEnableGroups(true);
//        //사용자 정의 DB를 사용하기 위한 커스텀 쿼리 작성
//        jdbcDao.setUsersByUsernameQuery(
//                "SELECT " +
//                        "login_id, passwd, true " +
//                        "FROM " +
//                        "users " +
//                        "WHERE " +
//                        "login_id = ?"
//        );
//        jdbcDao.setGroupAuthoritiesByUsernameQuery(
//                "SELECT " +
//                        "u.login_id, g.name, p.name " +
//                        "FROM " +
//                        "users u JOIN groups g ON u.group_id = g.id " +
//                        "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
//                        "JOIN permissions p ON p.id = gp.permission_id " +
//                        "WHERE " +
//                        "u.login_id = ?"
//        );
//        return jdbcDao;
//    }


    //    //Spring Mvc Async Request 없이, 별도의 스레드에서 SecurityContextHolder를 통해 SecurityContext를 얻을 수 있게 설정(권장 x)
//    public WebSecurityConfigure() {
//        //MODE_INHERITABLETHREADLOCAL 설정은 기본값인 MODE_THREADLOCAL와 다르게 부모 쓰레드의 변수를 자식 쓰레드도 참조할 수 있게 허용
//        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
//    }

    //ignoring()를 설정하지 않으면 CsrfFilter에 의해 /h2-console 페이지가 막힘
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
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

    public JwtAuthenticationFilter jwtAuthenticationFilter(Jwt jwt) {
        return new JwtAuthenticationFilter(
                this.jwtConfigure.getHeader(),
                jwt
        );
    }

    @Bean
    public OAuth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, Jwt jwt) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers(new AntPathRequestMatcher("/me")).hasAnyRole("USER", "ADMIN")
//                        .requestMatchers(new AntPathRequestMatcher("/admin")).hasRole("ADMIN")
//                        .requestMatchers(new AntPathRequestMatcher("/admin")).fullyAuthenticated()
                        .requestMatchers(new AntPathRequestMatcher("/api/user/me")).hasAnyRole("USER", "ADMIN")
                        .anyRequest().permitAll())
                .csrf(auth -> auth
                        .disable())
                .headers(auth -> auth
                        .disable())
                .sessionManagement(auth -> auth
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .formLogin(auth -> auth
//                        .defaultSuccessUrl("/")
//                        //.loginPage("/my-login") 직접 로그인 페이지 사용할 경우 설정
//                        .usernameParameter("my-username")
//                        .passwordParameter("my-password")
//                        .permitAll())
//                .logout(auth -> auth
//                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//                        .logoutSuccessUrl("/")
//                        .invalidateHttpSession(true)
//                        .clearAuthentication(true))
//                .rememberMe(auth -> auth
//                        .key("my-remember-me")
//                        .rememberMeParameter("remember-me")
//                        .tokenValiditySeconds(300))
//                .requiresChannel(auth -> auth
//                        .anyRequest().requiresSecure())
//                .anonymous(auth -> auth
//                        .principal("thisIsAnonymousUser")
//                        .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN"))
                .exceptionHandling(auth -> auth
                        .accessDeniedHandler(accessDeniedHandler()))
//                .sessionManagement(auth -> auth
//                        .sessionFixation().changeSessionId()
//                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
//                        .invalidSessionUrl("/")
//                        .maximumSessions(1)
//                        .maxSessionsPreventsLogin(false))
                .oauth2Login(auth -> auth
                        .successHandler(oauth2AuthenticationSuccessHandler()))
                .addFilterAfter(jwtAuthenticationFilter(jwt), SecurityContextHolderFilter.class)
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
