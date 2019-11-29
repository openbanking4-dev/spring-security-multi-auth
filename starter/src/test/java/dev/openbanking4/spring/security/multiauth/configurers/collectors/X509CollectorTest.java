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


import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import dev.openbanking4.spring.security.multiauth.model.granttypes.CustomGrantType;
import dev.openbanking4.spring.security.multiauth.model.granttypes.ScopeGrantType;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class X509CollectorTest {

    private X509Collector x509Collector;
    private String headerName = "x-cert";

    private String testCertificate =  "-----BEGIN CERTIFICATE-----\n" +
            "MIIFcjCCBFqgAwIBAgIUe+td+GoN8xuBQOh/C3jyT1jOL/AwDQYJKoZIhvcNAQEL\n" +
            "BQAwezELMAkGA1UEBhMCVUsxDTALBgNVBAgTBEF2b24xEDAOBgNVBAcTB0JyaXN0\n" +
            "b2wxEjAQBgNVBAoTCUZvcmdlUm9jazEcMBoGA1UECxMTZm9yZ2Vyb2NrLmZpbmFu\n" +
            "Y2lhbDEZMBcGA1UEAxMQb2JyaS1leHRlcm5hbC1jYTAgFw0xODA5MjYxMTIxMDZa\n" +
            "GA8yMTE5MDkwMjExMjEwNlowgb0xLTArBgNVBAMMJGZiNjEwOWFmLWYzZGQtNDQy\n" +
            "YS04YWQyLTY4Zjk0MzEwZDY0ZjEhMB8GA1UECwwYNWM0NWY4MmRhOTNiNzUwMTI1\n" +
            "YzdhZGViMRIwEAYDVQQKDAlGb3JnZVJvY2sxEDAOBgNVBAcMB0JyaXN0b2wxDTAL\n" +
            "BgNVBAgMBEF2b24xCzAJBgNVBAYTAlVLMScwJQYDVQRhDB5QU0RHQi01YzQ1Zjgy\n" +
            "ZGE5M2I3NTAxMjVjN2FkZWIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
            "AQCtevBE/KxBMRCxsqXh51qwrdWqtA0Y7NB8JxFG4JmgiKb0kVFfFyQ/rYALmy+F\n" +
            "Kf0hRq68vuPAAqXNIRHx+75gkC6cJ3KaMPPdNyTSzcR5S+PmAYg24a/LAAY+8iTV\n" +
            "qLQmdtSgtfF6tW1Dh7Jrpcp+0ePYl9YD5VAVHXB38w3d5tTFzp4KKcSh6oOI7xAr\n" +
            "gLoJOc9EudMlrecBlo3f2EtyZ4B5XDng7LSstBkETDiugFilDj/sj9nXU6ueXOK0\n" +
            "XiwxqVNxNlSlNhKRmdk+WEWPyX1/YHuPb6bPK+LqDef7i1WL0TvvzKq5JOt4XKuC\n" +
            "tXPP8aeOXpOkMnoN8cBxaIYJAgMBAAGjggGnMIIBozCBygYIKwYBBQUHAQEEgb0w\n" +
            "gbowWwYIKwYBBQUHMAKGT2h0dHBzOi8vc2VydmljZS5kaXJlY3Rvcnkub2IuZm9y\n" +
            "Z2Vyb2NrLmZpbmFuY2lhbDo0NDMvYXBpL2RpcmVjdG9yeS9rZXlzL2p3a191cmkw\n" +
            "WwYIKwYBBQUHMAGGT2h0dHBzOi8vc2VydmljZS5kaXJlY3Rvcnkub2IuZm9yZ2Vy\n" +
            "b2NrLmZpbmFuY2lhbDo0NDMvYXBpL2RpcmVjdG9yeS9rZXlzL2p3a191cmkwgdMG\n" +
            "CCsGAQUFBwEDBIHGMIHDMAgGBgQAjkYBATAJBgcEAI5GAQYDMAkGBwQAi+xJAQIw\n" +
            "gaAGBgQAgZgnAjCBlTBqMCkGBwQAgZgnAQQMHkNhcmQgQmFzZWQgUGF5bWVudCBJ\n" +
            "bnN0cnVtZW50czAeBgcEAIGYJwEDDBNBY2NvdW50IEluZm9ybWF0aW9uMB0GBwQA\n" +
            "gZgnAQIMElBheW1lbnQgSW5pdGlhdGlvbgwdRm9yZ2VSb2NrIEZpbmFuY2lhbCBB\n" +
            "dXRob3JpdHkMCEZSLUFBQUFBMA0GCSqGSIb3DQEBCwUAA4IBAQAyMykcsMA2qczZ\n" +
            "Rskwr0pdJx5JVII4GFBBW4c5zZO6S1Tx0RHCCCjhXvhtOCaMjT8aJRhlNdHrH8li\n" +
            "xCg0BDiZ6hEZ+ek2u9Jp0Y6yF6JcbUUqDmA1pltOEyQi/0ptBdEMawWk01b1AcTZ\n" +
            "IwhMI3sBPGEC/h1L7d2J0FRZJ5xjjI/WnO3HNnJZ7woE8lX5S7x8BvPyehkefEyd\n" +
            "NAauDEer1EQprbwrlhCGoyn/z/229gtCbDQU6QrDV2VfVg12oOMIDFLgTrxi0ua5\n" +
            "dolxvo7mWeu8kKkMHxOmi2CL99RXTfvehJPDcz0el596oIm0ltnxeY+UT3R7ODeK\n" +
            "LgOkXzbY\n" +
            "-----END CERTIFICATE-----\n";

    @Before
    public void setUp() {

        this.x509Collector =
                X509Collector.x509Builder()
                        .authoritiesCollector(certificatesChain -> Stream.of(CustomGrantType.INTERNAL).collect(Collectors.toSet()))
                        .usernameCollector(certificatesChain -> certificatesChain[0].getSubjectDN().getName())
                        .collectFromHeader(CertificateHeaderFormat.PEM)
                        .headerName(headerName)
                        .build();

    }

    @Test
    public void testAuthentication() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader(headerName)).thenReturn(testCertificate);

        //When
        Authentication authentication = x509Collector.collectAuthentication(mockedRequest);

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("OID.2.5.4.97=PSDGB-5c45f82da93b750125c7adeb, C=UK, ST=Avon, L=Bristol, O=ForgeRock, OU=5c45f82da93b750125c7adeb, CN=fb6109af-f3dd-442a-8ad2-68f94310d64f")
                .password("")
                .authorities(Collections.emptySet())
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();
        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());    }

    @Test
    public void testAuthorisation() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader(headerName)).thenReturn(testCertificate);

        ScopeGrantType accountsScope = new ScopeGrantType("accounts");

        //When
        Authentication authentication = x509Collector.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(accountsScope)));

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(CustomGrantType.INTERNAL, accountsScope).collect(Collectors.toSet()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }
}