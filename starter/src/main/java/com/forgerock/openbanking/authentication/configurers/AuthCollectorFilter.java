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
