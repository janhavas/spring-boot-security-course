package com.example.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.example.demo.security.ApplicationUserRole.ADMIN;
import static com.example.demo.security.ApplicationUserRole.STUDENT;
import static jakarta.servlet.DispatcherType.ERROR;
import static jakarta.servlet.DispatcherType.FORWARD;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests((authz) -> authz
                    //Dispatches FORWARD and ERROR are permitted to allow Spring MVC to render views and Spring Boot to render errors
                    .dispatcherTypeMatchers(FORWARD, ERROR).permitAll()
                    .requestMatchers("/", "index", "/css/*", "/js/*").permitAll()
                    .requestMatchers("/api/**").hasRole(STUDENT.name())
                    .anyRequest()
                    .authenticated())

    .httpBasic(Customizer.withDefaults());

    return http.build();
}

@Bean
protected UserDetailsService userDetailsService(){
    UserDetails user  = User.builder()
            .username("user")
            .password(passwordEncoder.encode("heslo"))
            .roles(STUDENT.name()) //ROLE_STUDENT
            .build();

    UserDetails admin  = User.builder()
            .username("admin")
            .password(passwordEncoder.encode("heslo123"))
            .roles(ADMIN.name()) //ROLE_ADMIN
            .build();

    return new InMemoryUserDetailsManager(user, admin);
}

}
