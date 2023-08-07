package com.prgrms.devcourse.configures;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfiguration {

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

    @Bean
    public UserDetailsService user() {

        UserDetails user = User.builder()
                .username("user")
                .password("{bcrypt}$2a$10$cv9M.jN4GgWUv0pFcCIHS.jpIpY7uFY8VnLos/8nZphaMItuRn/Hy")
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{bcrypt}$2a$10$75U1BZoGlw9VD43KsZQ9e.NmJyL4OEMaT0oE.LT6rvsI6NaHxV21m")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

}
