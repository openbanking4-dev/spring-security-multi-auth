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
package dev.openbanking4.spring.security.multiauth.configurers.collectors;

import dev.openbanking4.spring.security.multiauth.configurers.AuthCollector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import dev.openbanking4.spring.security.multiauth.model.authentication.X509Authentication;
import dev.openbanking4.spring.security.multiauth.utils.RequestUtils;
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

    private CertificateHeaderFormat collectFromHeader;
    private String headerName;

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

        X509Certificate[] certificatesChain = getX509Certificates(request);

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

    private X509Certificate[] getX509Certificates(HttpServletRequest request) {
        X509Certificate[] certificatesChain;

        if (collectFromHeader != null && request.getHeader(headerName) != null) {
            String certificatesSerialised = request.getHeader(headerName);
            log.debug("Found a certificate in the header '{}'", certificatesSerialised);
            certificatesChain = collectFromHeader.parseCertificate(certificatesSerialised).toArray(new X509Certificate[0]);
        } else {
            certificatesChain = RequestUtils.extractCertificatesChain(request);
        }
        return certificatesChain;
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

        X509Certificate[] certificatesChain = getX509Certificates(request);

        //Check if no client certificate received
        if (certificatesChain == null || certificatesChain.length == 0) {
            log.debug("No certificate received");
            return currentAuthentication;
        }

        Set<GrantedAuthority> authorities = authoritiesCollector.getAuthorities(certificatesChain);
        authorities.addAll(currentAuthentication.getAuthorities());

        return createAuthentication(currentAuthentication, certificatesChain, authorities);
    }

    protected Authentication createAuthentication(Authentication currentAuthentication, X509Certificate[] certificatesChain, Set<GrantedAuthority> authorities) {
        X509Authentication x509Authentication = new X509Authentication(currentAuthentication.getName(), authorities, certificatesChain);
        x509Authentication.setAuthenticated(currentAuthentication.isAuthenticated());
        return x509Authentication;
    }

    public interface UsernameCollector {
        String getUserName(X509Certificate[] certificatesChain);
    }

    public interface AuthoritiesCollector {
        Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain);
    }
}
