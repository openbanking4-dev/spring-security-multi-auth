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

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.eidas.EidasCertType;
import com.forgerock.cert.exception.InvalidEidasCertType;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.psd2.Psd2QcStatement;
import com.forgerock.cert.psd2.RolesOfPsp;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.authentication.PSD2Authentication;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Slf4j
public class PSD2Collector extends X509Collector {
    @Builder
    public PSD2Collector(UsernameCollector usernameCollector, AuthoritiesCollector authoritiesCollector, CertificateHeaderFormat collectFromHeader, String headerName) {
        super(usernameCollector, certificatesChain -> {
            Set<GrantedAuthority> authorities = new HashSet<>();
            try {
                Psd2CertInfo psd2CertInfo = new Psd2CertInfo(certificatesChain);
                if (psd2CertInfo.isPsd2Cert()
                        && psd2CertInfo.getEidasCertType().isPresent()
                        && psd2CertInfo.getEidasCertType().get().equals(EidasCertType.WEB)) {

                    //Map PSD2 roles
                    Optional<Psd2QcStatement> psd2QcStatementOpt = psd2CertInfo.getPsd2QCStatement();
                    if (psd2QcStatementOpt.isPresent()) {
                        Psd2QcStatement psd2QcStatement = psd2QcStatementOpt.get();
                        authorities.addAll(authoritiesCollector.getAuthorities(certificatesChain, psd2CertInfo, psd2QcStatement.getRoles()));
                    } else {
                        authorities.addAll(authoritiesCollector.getAuthorities(certificatesChain, psd2CertInfo, null));
                    }
                }
            } catch (InvalidPsd2EidasCertificate | InvalidEidasCertType invalidPsd2EidasCertificate) {
                invalidPsd2EidasCertificate.printStackTrace();
            }

            authorities.addAll(authoritiesCollector.getAuthorities(certificatesChain, null, null));
            return authorities;
        }, collectFromHeader, headerName);
    }


    @Override
    protected Authentication createAuthentication(Authentication currentAuthentication, X509Certificate[] certificatesChain, Set<GrantedAuthority> authorities) {
        try {
            Psd2CertInfo psd2CertInfo = new Psd2CertInfo(certificatesChain);

            if (psd2CertInfo.isPsd2Cert()
                    && psd2CertInfo.getEidasCertType().isPresent()
                    && psd2CertInfo.getEidasCertType().get().equals(EidasCertType.WEB)) {

            }
            PSD2Authentication psd2Authentication = new PSD2Authentication(currentAuthentication.getName(), authorities, certificatesChain, psd2CertInfo);
            psd2Authentication.setAuthenticated(currentAuthentication.isAuthenticated());
            return psd2Authentication;
        } catch (InvalidPsd2EidasCertificate | InvalidEidasCertType invalidPsd2EidasCertificate) {
        }
        return super.createAuthentication(currentAuthentication, certificatesChain, authorities);
    }

    public interface AuthoritiesCollector {
        Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles);
    }
}
