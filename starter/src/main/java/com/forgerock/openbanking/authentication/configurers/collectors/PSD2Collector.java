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

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.eidas.EidasCertType;
import com.forgerock.cert.exception.InvalidEidasCertType;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.psd2.Psd2QcStatement;
import com.forgerock.cert.psd2.RolesOfPsp;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Slf4j
public class PSD2Collector extends X509Collector {
    @Builder
    public PSD2Collector(UsernameCollector usernameCollector, AuthoritiesCollector authoritiesCollector) {
        super(usernameCollector, certificatesChain -> {
            Set<GrantedAuthority> authorities = new HashSet<>();
            try {
                Psd2CertInfo psd2CertInfo = new Psd2CertInfo(certificatesChain);
                if (psd2CertInfo.isPsd2Cert()
                        && psd2CertInfo.getEidasCertType().isPresent()
                        && psd2CertInfo.getEidasCertType().equals(EidasCertType.WEB)) {

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
        });
    }

    public interface AuthoritiesCollector {
        Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles);
    }
}
