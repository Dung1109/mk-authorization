package org.andy.democloudgatewayauth.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.andy.democloudgatewayauth.service.OidcUserInfoService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.time.Duration;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Configuration(proxyBeanMethods = false)
@Slf4j
@RequiredArgsConstructor
public class AuthorizationServerConfig {


    // @formatter:off
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    SecurityFilterChain authorizationSecurityFilterChain(HttpSecurity http) throws Exception {

//        applyDefaultSecurity(http);

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();
        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                        .authorizeHttpRequests(authorizeRequests ->
                                authorizeRequests.anyRequest().authenticated()
                        );

//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());

        // (1)
        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> {
            OidcUserInfoAuthenticationToken authenticationToken = context.getAuthentication();
            JwtAuthenticationToken principal = (JwtAuthenticationToken) authenticationToken.getPrincipal();

            return new OidcUserInfo(principal.getToken().getClaims());
        };

        var authServerConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        // (2)
        authServerConfigurer.oidc((oidc) -> oidc.userInfoEndpoint((userInfo) -> userInfo
                .userInfoMapper(userInfoMapper)));

        return http
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .exceptionHandling(c ->
                        c.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))

                .formLogin(Customizer.withDefaults())
                .build();
    }
    // @formatter:on


    @Bean
    public JdbcRegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {

        RegisteredClient messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
//                .scope("u.test")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(30L)).refreshTokenTimeToLive(Duration.ofMinutes(60L)).build())
                .build();

        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        registeredClientRepository.save(messagingClient);
        return registeredClientRepository;
    }


    @Bean
    public JdbcOAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }




    @Bean
    public JdbcOAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
//        return (context) -> {
//            if(OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//                log.debug("Adding roles to access token");
//                log.debug("authorities: {}", context.getPrincipal().getAuthorities());
//
//                context.getClaims().claims((claims) -> {
//                    Set<String> roles = AuthorityUtils.authorityListToSet(
//                                    context.getPrincipal().getAuthorities())
//                            .stream()
//                            .map((authority) -> authority.replaceFirst("^ROLE_", ""))
//                            .collect(Collectors
//                                    .collectingAndThen(Collectors.toSet(),
//                                            Collections::unmodifiableSet));
//
//                    log.debug("roles: {}", roles);
//                    claims.put("roles", roles);
//                });
//            }
//        };
//    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(
            OidcUserInfoService oidcUserInfoService) {

        return (context) -> {

            log.info("=====> context.getTokenType(): {}", context.getTokenType().getValue());

            // (1)
            if(OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                log.debug("Adding claims to id token");

                var principal = context.getPrincipal();
                log.info("principal: {}, class: {}", principal, principal.getClass());

                OidcUserInfo userInfo = oidcUserInfoService.loadUser(
                        context.getPrincipal().getName());

                log.debug("claims: {}", userInfo.getClaims());
                context.getClaims().claims(claims -> {
                    claims.putAll(userInfo.getClaims());
                });
            }
            // (2)
            if(OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                log.debug("Adding roles to access token");
                log.debug("authorities: {}", context.getPrincipal().getAuthorities());

                context.getClaims().claims((claims) -> {
                    Set<String> roles = AuthorityUtils.authorityListToSet(
                                    context.getPrincipal().getAuthorities())
                            .stream()
                            .map((authority) -> authority.replaceFirst("^ROLE_", ""))
                            .collect(Collectors
                                    .collectingAndThen(Collectors.toSet(),
                                            Collections::unmodifiableSet));

                    log.debug("roles: {}", roles);
                    claims.put("roles", roles);

                    OidcUserInfo userInfo = oidcUserInfoService.loadUser(
                            context.getPrincipal().getName());

                    claims.put("email", userInfo.getEmail());
                });
            }
        };
    }
}