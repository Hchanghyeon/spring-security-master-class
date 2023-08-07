package com.prgrms.devcourse.configures;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfiguration {

    private DataSource dataSource;

    @Autowired
    private void setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**"))
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(new AntPathRequestMatcher("/me")).hasAnyRole("USER", "ADMIN")
                        .anyRequest().permitAll()
                )
                .formLogin(form -> form
                        .defaultSuccessUrl("/")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                )
                .rememberMe(remember -> remember
                        .tokenValiditySeconds(300)
                )
                .requiresChannel(channel -> channel
                        .anyRequest().requiresSecure()
                )
                .headers(headers -> headers
                        .frameOptions(FrameOptionsConfig::sameOrigin)
                );

        return http.build();
    }

    @Autowired
    public void jdbcAuthentication(AuthenticationManagerBuilder auth) throws Exception {

        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .passwordEncoder(new BCryptPasswordEncoder())
                .usersByUsernameQuery(
                        "SELECT " +
                                "login_id, passwd, true " +
                                "FROM " +
                                "users " +
                                "WHERE " +
                                "login_id = ?"
                )
                .groupAuthoritiesByUsername(
                        "SELECT " +
                                "u.login_id, g.name, p.name " +
                                "FROM " +
                                "users u JOIN groups g ON u.group_id = g.id " +
                                "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
                                "JOIN permissions p ON p.id = gp.permission_id " +
                                "WHERE " +
                                "u.login_id = ?"
                )
                .getUserDetailsService().setEnableAuthorities(false);
    }
}
