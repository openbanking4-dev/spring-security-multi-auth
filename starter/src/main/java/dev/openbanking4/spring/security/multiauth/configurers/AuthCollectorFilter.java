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

import dev.openbanking4.spring.security.multiauth.model.authentication.AuthenticationWithEditableAuthorities;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Slf4j
@AllArgsConstructor
public class AuthCollectorFilter extends OncePerRequestFilter {

    private List<AuthCollector> authenticationCollectors;
    private List<AuthCollector> authorizationCollectors;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        AuthenticationWithEditableAuthorities currentAuthentication = null;
        log.trace("Going through all the collectors to authenticate the request, in the order of setup");
        for (AuthCollector authCollector : authenticationCollectors) {
            log.trace("Collector name: '{}'", authCollector.collectorName());

            log.trace("Verify is setup correctly to handle authentication");
            if (!authCollector.isSetupForAuthentication()) {
                log.warn("You forgot to setup the username collector. Either setup a username " +
                        "collector or setup this collector '" + authCollector.collectorName() + "' to only handle authorization");
                continue;
            }
            currentAuthentication = authCollector.collectAuthentication(request);
            if (currentAuthentication != null) {
                log.trace("Collector founds an authentication, skip next collectors");
                break;
            } else {
                log.trace("Collector didn't managed to find an authentication");
            }
        }

        if (currentAuthentication == null) {
            log.trace("No authentication founds by any of the collectors");
            chain.doFilter(request, response);
            return;
        }

        currentAuthentication.setAuthenticated(true);

        log.trace("Going through all the collectors to authorize the request");
        for (AuthCollector authCollector : authorizationCollectors) {
            log.trace("Collector name: '{}'", authCollector.collectorName());
            log.trace("Verify is setup correctly to handle authorisation");
            if (!authCollector.isSetupForAuthorisation()) {
                log.warn("You forgot to setup the authorities collector. Either setup an authorities " +
                        "collector or setup this collector '" + authCollector.collectorName() + "' to only handle authentication");
                continue;
            }
            currentAuthentication = authCollector.collectAuthorisation(request, (AuthenticationWithEditableAuthorities) currentAuthentication);
        }
        if (currentAuthentication != null) {
            log.trace("Authentication computed by the multi-auth: {}", currentAuthentication);
            SecurityContextHolder.getContext().setAuthentication(currentAuthentication);
        }

        chain.doFilter(request, response);
    }


}
