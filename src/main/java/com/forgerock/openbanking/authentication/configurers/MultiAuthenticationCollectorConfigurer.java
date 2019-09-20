package com.forgerock.openbanking.authentication.configurers;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;


public class MultiAuthenticationCollectorConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<X509Configurer<H>, H> {

    private List<AuthCollector> authentificationCollectors = new ArrayList<>();
    private List<AuthCollector> authorizationCollectors = new ArrayList<>();
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService;


    public MultiAuthenticationCollectorConfigurer<H> collector(AuthCollector authCollector) {
        this.authentificationCollectors.add(authCollector);
        this.authorizationCollectors.add(authCollector);
        return this;
    }

    public MultiAuthenticationCollectorConfigurer<H> collectorForAuthentication(AuthCollector authCollector) {
        this.authentificationCollectors.add(authCollector);
        return this;
    }

    public MultiAuthenticationCollectorConfigurer<H> collectorForAuthorzation(AuthCollector authCollector) {
        this.authorizationCollectors.add(authCollector);
        return this;
    }

    public void configure(H http) {
        AuthCollectorFilter filter = new AuthCollectorFilter(authentificationCollectors, authorizationCollectors);
        filter = this.postProcess(filter);
        http.addFilterBefore(filter, BasicAuthenticationFilter.class);
        PreAuthenticatedAuthenticationProvider authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(this.getAuthenticationUserDetailsService(http));
        http.authenticationProvider(authenticationProvider).setSharedObject(AuthenticationEntryPoint.class, new Http403ForbiddenEntryPoint());
    }

    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> getAuthenticationUserDetailsService(H http) {
        if (this.authenticationUserDetailsService == null) {
            this.userDetailsService(http.getSharedObject(UserDetailsService.class));
        }

        return this.authenticationUserDetailsService;
    }

    public MultiAuthenticationCollectorConfigurer<H> userDetailsService(UserDetailsService userDetailsService) {
        UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService = new UserDetailsByNameServiceWrapper();
        authenticationUserDetailsService.setUserDetailsService(userDetailsService);
        return this.authenticationUserDetailsService(authenticationUserDetailsService);
    }


    public MultiAuthenticationCollectorConfigurer<H> authenticationUserDetailsService(AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService) {
        this.authenticationUserDetailsService = authenticationUserDetailsService;
        return this;
    }
}
