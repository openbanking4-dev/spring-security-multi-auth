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
package dev.openbanking4.spring.security.multiauth.model;

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
