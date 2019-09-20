/*
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

import com.forgerock.openbanking.authentication.model.authentication.PasswordLessUserNameAuthentication;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Slf4j
@AllArgsConstructor
public class AuthCollectorFilter extends GenericFilterBean {

    private List<AuthCollector> authentificationCollectors;
    private List<AuthCollector> authorizationCollectors;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;
        for (AuthCollector authCollector : authentificationCollectors) {
            Authentication authentication = authCollector.collectAuthentication((HttpServletRequest) req);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
                break;
            }
        }

        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (currentAuthentication == null) {
            currentAuthentication = new PasswordLessUserNameAuthentication("", Collections.EMPTY_SET);
        } else {
            currentAuthentication.setAuthenticated(true);
        }

        for (AuthCollector authCollector : authorizationCollectors) {
            currentAuthentication = authCollector.collectAuthorisation((HttpServletRequest) req, currentAuthentication);
        }
        if (currentAuthentication != null) {
            SecurityContextHolder.getContext().setAuthentication(currentAuthentication);
        }
        chain.doFilter(request, response);
    }

}
