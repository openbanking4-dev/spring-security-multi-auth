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
package com.forgerock.openbanking.authentication.model;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
public enum CertificateHeaderFormat {

    PEM {
        @Override
        public List<X509Certificate> parseCertificate(String pem) {
            log.debug("Extract the certificate from a pem {}", pem);
            try {
                byte [] decoded = Base64.getDecoder()
                        .decode(
                                pem
                                        .replaceAll("\n", "")
                                        .replaceAll(BEGIN_CERT, "")
                                        .replaceAll(END_CERT, ""));
                return Stream.of(
                        (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded))
                ).collect(Collectors.toList());
            } catch (CertificateException e) {
                log.error("Can't initialise certificate factory", e);
            }
            return null;
        }
    }, JWK {
        @Override
        public  List<X509Certificate> parseCertificate(String jwkSerialised) {
            log.debug("Extract the certificate from the JWK");
            try {
                JWK jwk = com.nimbusds.jose.jwk.JWK.parse(jwkSerialised);
                return jwk.getParsedX509CertChain();
            } catch (ParseException e) {
                log.error("Can't parse x509 certificate", e);
            }
            return null;
        }
    };

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";

    public abstract  List<X509Certificate> parseCertificate(String certStr);
}
