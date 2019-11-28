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

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
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

    private List<AuthCollector> authentificationCollectors;
    private List<AuthCollector> authorizationCollectors;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        Authentication currentAuthentication = null;
        for (AuthCollector authCollector : authentificationCollectors) {
            currentAuthentication = authCollector.collectAuthentication(request);
            if (currentAuthentication != null) {
                break;
            }
        }

        if (currentAuthentication == null) {
            chain.doFilter(request, response);
            return;
        }

        currentAuthentication.setAuthenticated(true);

        for (AuthCollector authCollector : authorizationCollectors) {
            currentAuthentication = authCollector.collectAuthorisation(request, currentAuthentication);
        }
        if (currentAuthentication != null) {
            SecurityContextHolder.getContext().setAuthentication(currentAuthentication);
        }

        chain.doFilter(request, response);
    }


}
