/**
 * The contents of this file are subject to the terms of the Common Development and
 *  Distribution License (the License). You may not use this file except in compliance with the
 *  License.
 *
 *  You can obtain a copy of the License at https://forgerock.org/cddlv1-0/. See the License for the
 *  specific language governing permission and limitations under the License.
 *
 *  When distributing Covered Software, include this CDDL Header Notice in each file and include
 *  the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 *  Header, with the fields enclosed by brackets [] replaced by your own identifying
 *  information: "Portions copyright [year] [name of copyright owner]".
 *
 *  Copyright 2019 ForgeRock AS.
 */
package com.forgerock.openbanking.authentication.configurers;

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
