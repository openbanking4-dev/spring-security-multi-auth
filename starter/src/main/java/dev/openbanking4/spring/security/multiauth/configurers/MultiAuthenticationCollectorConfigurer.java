/**
 * Copyright 2019 Quentin Castel.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package dev.openbanking4.spring.security.multiauth.configurers;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;


public class MultiAuthenticationCollectorConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<X509Configurer<H>, H> {

    private List<AuthCollector> authentificationCollectors = new ArrayList<>();
    private List<AuthCollector> authorizationCollectors = new ArrayList<>();
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService;
    private AuthenticationFailureHandler authenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler();

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
        AuthCollectorFilter filter = new AuthCollectorFilter(authentificationCollectors, authorizationCollectors, authenticationFailureHandler);
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
