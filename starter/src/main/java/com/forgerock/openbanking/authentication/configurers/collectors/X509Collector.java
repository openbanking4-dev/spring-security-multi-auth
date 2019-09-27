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
package com.forgerock.openbanking.authentication.configurers.collectors;

import com.forgerock.openbanking.authentication.configurers.AuthCollector;
import com.forgerock.openbanking.authentication.model.authentication.PasswordLessUserNameAuthentication;
import com.forgerock.openbanking.authentication.utils.RequestUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

@Slf4j
@AllArgsConstructor
public class X509Collector implements AuthCollector {

    private UsernameCollector usernameCollector;
    private AuthoritiesCollector authoritiesCollector;

    @Override
    public Authentication collectAuthentication(HttpServletRequest request) {


        if (RequestContextHolder.getRequestAttributes() == null) {
            log.warn("No request attributes available!");
            return null;
        }
        if (request == null) {
            log.warn("No request received!");
            return null;
        }

        X509Certificate[] certificatesChain = RequestUtils.extractCertificatesChain(request);

        //Check if no client certificate received
        if (certificatesChain == null || certificatesChain.length == 0) {
            log.debug("No certificate received");
            return null;
        }

        String username = usernameCollector.getUserName(certificatesChain);
        if (username == null) {
            return null;
        }

        return new PasswordLessUserNameAuthentication(username, Collections.EMPTY_SET);
    }

    @Override
    public Authentication collectAuthorisation(HttpServletRequest request, Authentication currentAuthentication) {

        if (RequestContextHolder.getRequestAttributes() == null) {
            log.warn("No request attributes available!");
            return currentAuthentication;
        }
        if (request == null) {
            log.warn("No request received!");
            return currentAuthentication;
        }

        X509Certificate[] certificatesChain = RequestUtils.extractCertificatesChain(request);

        //Check if no client certificate received
        if (certificatesChain == null || certificatesChain.length == 0) {
            log.debug("No certificate received");
            return currentAuthentication;
        }

        Set<GrantedAuthority> authorities = authoritiesCollector.getAuthorities(certificatesChain);
        authorities.addAll(currentAuthentication.getAuthorities());

        PasswordLessUserNameAuthentication passwordLessUserNameAuthentication = new PasswordLessUserNameAuthentication(currentAuthentication.getName(), authorities);
        passwordLessUserNameAuthentication.setAuthenticated(currentAuthentication.isAuthenticated());
        return passwordLessUserNameAuthentication;
    }

    public interface UsernameCollector {
        String getUserName(X509Certificate[] certificatesChain);
    }

    public interface AuthoritiesCollector {
        Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain);
    }
}
