package com.azure.spring.admin.server.security;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import static com.azure.spring.cloud.autoconfigure.implementation.aad.security.AadWebApplicationHttpSecurityConfigurer.aadWebApplication;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    private final AdminServerProperties adminServer;

    public SecurityConfig(AdminServerProperties adminServer) {
        this.adminServer = adminServer;
    }

    @Bean
    public SecurityFilterChain htmlFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http.apply(aadWebApplication());
        String homeUrl;
        if (StringUtils.hasText(this.adminServer.getContextPath())) {
            homeUrl = this.adminServer.getContextPath();
        } else {
            homeUrl="/";
        }
        http.authorizeHttpRequests(requests ->
                requests.requestMatchers(EndpointRequest.to(HealthEndpoint.class), // availability test for Application Insights
                            new AntPathRequestMatcher(this.adminServer.path("/assets/**")),
                            new AntPathRequestMatcher(this.adminServer.path("/login"))).permitAll()
                        .anyRequest().authenticated())
            .oauth2Login(login -> login.defaultSuccessUrl(homeUrl))
            .csrf(csrf-> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                             .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                             .ignoringRequestMatchers(new AntPathRequestMatcher(this.adminServer.path("/instances"), HttpMethod.POST.toString()),
                                 new AntPathRequestMatcher(this.adminServer.path("/instances/*"), HttpMethod.DELETE.toString()),
                                 new AntPathRequestMatcher(this.adminServer.path("/actuator/**"))))
            .logout(logout -> logout.logoutUrl(this.adminServer.path("/logout"))
                                    .logoutSuccessUrl("/login"));
        // @formatter:on
        return http.build();
    }
}