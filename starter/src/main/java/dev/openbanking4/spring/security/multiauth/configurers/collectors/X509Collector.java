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
package dev.openbanking4.spring.security.multiauth.configurers.collectors;

import dev.openbanking4.spring.security.multiauth.configurers.AuthCollector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import dev.openbanking4.spring.security.multiauth.model.authentication.X509Authentication;
import dev.openbanking4.spring.security.multiauth.utils.RequestUtils;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

@Slf4j
public class X509Collector implements AuthCollector {

    private UsernameCollector usernameCollector;
    private AuthoritiesCollector authoritiesCollector;

    private CertificateHeaderFormat collectFromHeader;
    private String headerName;

    @Builder(builderMethodName = "x509Builder")
    public X509Collector(String collectorName,
            UsernameCollector usernameCollector,
            AuthoritiesCollector authoritiesCollector,
            CertificateHeaderFormat collectFromHeader,
            String headerName) {
        this.collectorName = collectorName;
        this.usernameCollector = usernameCollector;
        this.authoritiesCollector = authoritiesCollector;
        this.collectFromHeader = collectFromHeader;
        this.headerName = headerName;
    }

    private String collectorName;

    @Override
    public String collectorName() {
        return collectorName;
    }

    @Override
    public Authentication collectAuthentication(HttpServletRequest request) {

        X509Certificate[] certificatesChain = getCertificatesFromRequest(request);

        //Check if no client certificate received
        if (certificatesChain == null) {
            return null;
        }

        String username = usernameCollector.getUserName(certificatesChain);
        log.trace("Username '{}' extracted from the certificate", username);

        if (username == null) {
            return null;
        }

        return new PasswordLessUserNameAuthentication(username, Collections.EMPTY_SET);
    }


    @Override
    public Authentication collectAuthorisation(HttpServletRequest request, Authentication currentAuthentication) {

        X509Certificate[] certificatesChain = getCertificatesFromRequest(request);

        //Check if no client certificate received
        if (certificatesChain == null) {
            return currentAuthentication;
        }

        Set<GrantedAuthority> authorities = authoritiesCollector.getAuthorities(certificatesChain);
        log.trace("Authorities founds: {}", authorities);

        authorities.addAll(currentAuthentication.getAuthorities());
        log.trace("Final authorities merged with previous authorities: {}", authorities);

        return createAuthentication(currentAuthentication, certificatesChain, authorities);
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

    protected X509Certificate[] getCertificatesFromRequest(HttpServletRequest request) {
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

        return certificatesChain;
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
