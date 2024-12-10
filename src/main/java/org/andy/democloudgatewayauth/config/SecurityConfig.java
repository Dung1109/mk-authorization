package org.andy.democloudgatewayauth.config;

import lombok.extern.slf4j.Slf4j;
import org.andy.democloudgatewayauth.federation.FederatedIdentityAuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.sql.DataSource;

@Configuration(proxyBeanMethods = false)
@Slf4j
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

//    @Bean
//    PasswordEncoder passwordEncoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }

    @Bean
    UserDetailsPasswordService userDetailsPasswordService(UserDetailsManager udm) {
        return (user, newPassword) -> {
            var updated = User.withUserDetails(user)
                    .password(newPassword)
                    .build();
            udm.updateUser(updated);
            return updated;
        };
    }


    @Bean
        // @formatter:off
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        final var allowedUris = new String[] {
                "/error",
                "/actuator/health",
                "/actuator/health/liveness",
                "/actuator/health/readiness"
        };

        return http
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests.requestMatchers(allowedUris).permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(
                        login -> login
                                .loginPage("/login")
                                .permitAll()
                )
                .build();
    }
    // @formatter:on

    private AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new FederatedIdentityAuthenticationSuccessHandler();
    }

}
