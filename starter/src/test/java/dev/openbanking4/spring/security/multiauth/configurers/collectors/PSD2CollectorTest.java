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


import com.forgerock.cert.psd2.Psd2Role;
import com.forgerock.cert.psd2.RoleOfPsp;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import dev.openbanking4.spring.security.multiauth.model.granttypes.PSD2GrantType;
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
public class PSD2CollectorTest {

    private PSD2Collector psd2Collector;
    private String headerName = "x-cert";

    private String testPSD2Certificate =  "-----BEGIN CERTIFICATE-----\n" +
            "MIIFoDCCBIigAwIBAgIEWcWcQDANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJH\n" +
            "QjEUMBIGA1UEChMLT3BlbkJhbmtpbmcxLjAsBgNVBAMTJU9wZW5CYW5raW5nIFBy\n" +
            "ZS1Qcm9kdWN0aW9uIElzc3VpbmcgQ0EwHhcNMTkwODE5MTUzMTU2WhcNMjAwOTE5\n" +
            "MTYwMTU2WjBeMQswCQYDVQQGEwJHQjEWMBQGA1UEChMNVGVzdCBCYW5rIFBMQzEa\n" +
            "MBgGA1UEYRMRUFNER0ItVEVTVC0xMjM0NTYxGzAZBgNVBAMTEjAwMTU4MDAwMDFI\n" +
            "UVFycEFBSDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOPbgEZW7bLj\n" +
            "DzF2uJHpTwLk3lSX4updSyuR2Bp8XKIDgQcONWLa++U5n5vzarO/ZLr7f6f0dbnN\n" +
            "LI9CP3yFmUhjeDwE/d7VLD+vqygv3aDFDhshiCf956SmO4rNAMzUYMXIeSEmfuzi\n" +
            "USjL/bd80ftljrn2LSGnZqG/HamlLKdoYvnvtFlSHr2eUScu2rjmbEC+ZxQKQsSA\n" +
            "luoRfXi8/2QSXlqzapbCPrToFytDDbkoisv+r38Jc+rYuKQFScmb5XJdhHgIWzWa\n" +
            "ZMPPhsp6REw640GQgpiLk5rQbPj6zGAH4vGJUJmvu8oq4y6q/nPkpHxGDfUuDrIN\n" +
            "Rye+Vwm8gZcCAwEAAaOCAm8wggJrMA4GA1UdDwEB/wQEAwIHgDBpBggrBgEFBQcB\n" +
            "AwRdMFswEwYGBACORgEGMAkGBwQAjkYBBgMwRAYGBACBmCcCMDowEzARBgcEAIGY\n" +
            "JwEDDAZQU1BfQUkMG0ZpbmFuY2lhbCBDb25kdWN0IEF1dGhvcml0eQwGR0ItRkNB\n" +
            "MCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCB4AYDVR0gBIHYMIHV\n" +
            "MIHSBgsrBgEEAah1gQYBZDCBwjAqBggrBgEFBQcCARYeaHR0cDovL29iLnRydXN0\n" +
            "aXMuY29tL3BvbGljaWVzMIGTBggrBgEFBQcCAjCBhgyBg1VzZSBvZiB0aGlzIENl\n" +
            "cnRpZmljYXRlIGNvbnN0aXR1dGVzIGFjY2VwdGFuY2Ugb2YgdGhlIE9wZW5CYW5r\n" +
            "aW5nIFJvb3QgQ0EgQ2VydGlmaWNhdGlvbiBQb2xpY2llcyBhbmQgQ2VydGlmaWNh\n" +
            "dGUgUHJhY3RpY2UgU3RhdGVtZW50MG0GCCsGAQUFBwEBBGEwXzAmBggrBgEFBQcw\n" +
            "AYYaaHR0cDovL29iLnRydXN0aXMuY29tL29jc3AwNQYIKwYBBQUHMAKGKWh0dHA6\n" +
            "Ly9vYi50cnVzdGlzLmNvbS9vYl9wcF9pc3N1aW5nY2EuY3J0MDoGA1UdHwQzMDEw\n" +
            "L6AtoCuGKWh0dHA6Ly9vYi50cnVzdGlzLmNvbS9vYl9wcF9pc3N1aW5nY2EuY3Js\n" +
            "MB8GA1UdIwQYMBaAFFBzkcYhctN39P4AEgaBXHl5bj9QMB0GA1UdDgQWBBSApq4j\n" +
            "eB3V32VCf7m2n/dVkj6V2zANBgkqhkiG9w0BAQsFAAOCAQEAjSg6xnezKLzU7Svg\n" +
            "gMg9pDdcYQ5SZp7AMaepp2zm4q0JE166b9Rb/YCzrnjy+kDf1HheTsU5QiA+CeYI\n" +
            "ATFir6RXrAUy2opbf9vH8w9Ydqh7sfjhIdrMP4fqSdJ1OkQmPaVK9PZ3DXgtdPHu\n" +
            "Rdx5wL/dQlnETnV1rmnl2jdsXkq78e+ZggiY5a0U54AcDcrVIRGE7sRwFDRIqVYU\n" +
            "lOfaTSShkUvyR3J8O0/ZnFIaNa59Rn1jiPJwxc2NBnRWaAK7uYojui/dUa7Oj4IF\n" +
            "A5+aIsJQ0MAgofRQUweSbolFzjLhxjB87BYy0Lfxf300eN15LB5o/e3BIcIstP74\n" +
            "NUL7Aw==\n" +
            "-----END CERTIFICATE-----\n";

    public String testNonPSD2Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGeTCCBWGgAwIBAgIRAMCIY4gkrmSd54opOFMe/MgwDQYJKoZIhvcNAQELBQAw\n" +
            "gZAxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO\n" +
            "BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTYwNAYD\n" +
            "VQQDEy1DT01PRE8gUlNBIERvbWFpbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2ZXIg\n" +
            "Q0EwHhcNMTYxMTE2MDAwMDAwWhcNMjAwMjE1MjM1OTU5WjCBgTEhMB8GA1UECxMY\n" +
            "RG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMSQwIgYDVQQLExtIb3N0ZWQgYnkgQmx1\n" +
            "ZUhvc3QuQ29tLCBJTkMxHTAbBgNVBAsTFFBvc2l0aXZlU1NMIFdpbGRjYXJkMRcw\n" +
            "FQYDVQQDDA4qLmJsdWVob3N0LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC\n" +
            "AgoCggIBALR9io8CY+h6wacVfo24XA/w7XSy3BeRB1W0xgPNVJ9OiQE2Zhs7oNS5\n" +
            "Cpsq/6Ueqv5Y0pdS6joGXQ60lkLD3xhmx4lTmYN0pwp4o95Lzv6PxiIQ4V7Zz4+4\n" +
            "E+4Ic1glSBBT4ANwH/N+Wr8Gw4TvQDoKOPXwR9tBaqTIRh9FxiefTDkYAGdpzPSd\n" +
            "/ZhqMam3SaW+209atUu5KmGtisFIbiolTFNSWJRR8MB5xZzbBVYwVwA4A3K8Q6/O\n" +
            "S5GmokRFsn93goeeUpv+erDyP6VM9d3pu5QNyn4wW5eexUYl9CSXbUgoSUu3UsYo\n" +
            "gaVVSAf3LfPWmmcOMXmEDfjCCG399FQmSDsCHZdimxBrHERlWV09UHIryICgsJqd\n" +
            "sFLXSm/FxjQJ0/3DPDotqmaiEGYdgL1VQuqpYHXDv8JgB0GgJ/ufHnpq3+KuNMfp\n" +
            "SSBGhGPbeo3QGY/Uz1BB58UJRWTWhqghaKP+8MG4yPylQ1TMbZcabkcX8PbyxdRd\n" +
            "4k2q2nktM+WNUCKQ4240f3Ujey8s/63kxXb22Y59rX44sYr4kuMAxDN4ztmPPGsq\n" +
            "+46NnjE9DGaW255rnv3C3MA05bPETY/E1CvU7i3AZRYQwGGlAkSXCbS4htREaF83\n" +
            "UrFXvFyoZf1Nci1mMOnS7y92Ad2M7JDkVtGCVLl9aXYz+BxEE9uPAgMBAAGjggHZ\n" +
            "MIIB1TAfBgNVHSMEGDAWgBSQr2o6lFoL2JDqElZz30O0Oija5zAdBgNVHQ4EFgQU\n" +
            "1H1KPlLcvK6JP/e/+okqjj0HrgQwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQC\n" +
            "MAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCME8GA1UdIARIMEYwOgYL\n" +
            "KwYBBAGyMQECAgcwKzApBggrBgEFBQcCARYdaHR0cHM6Ly9zZWN1cmUuY29tb2Rv\n" +
            "LmNvbS9DUFMwCAYGZ4EMAQIBMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly9jcmwu\n" +
            "Y29tb2RvY2EuY29tL0NPTU9ET1JTQURvbWFpblZhbGlkYXRpb25TZWN1cmVTZXJ2\n" +
            "ZXJDQS5jcmwwgYUGCCsGAQUFBwEBBHkwdzBPBggrBgEFBQcwAoZDaHR0cDovL2Ny\n" +
            "dC5jb21vZG9jYS5jb20vQ09NT0RPUlNBRG9tYWluVmFsaWRhdGlvblNlY3VyZVNl\n" +
            "cnZlckNBLmNydDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29t\n" +
            "MCcGA1UdEQQgMB6CDiouYmx1ZWhvc3QuY29tggxibHVlaG9zdC5jb20wDQYJKoZI\n" +
            "hvcNAQELBQADggEBAIwvxYYexAF23mL9r0uOX268z6D66HRtLwopZT0IzxqNdVD1\n" +
            "FUm7yOCvGpytCa0dFxa9wT5PSewoZk+HRI5K7AjrURpg+JOHFa4A5VGirmM7S819\n" +
            "/LAN39JJ0UWfy1EZcgBuGzfO5Tt2UpKwi8mZ81+uJTFa8Vxu1NCf/uHJIHUUkrCY\n" +
            "bVAJQbulHD8tDmfwj255QwegWzHkqkY9VRMqL4MvuBseNNnX4FAk0+05DNPeWpuk\n" +
            "/ynPUL3T8/DMQaOgOdin4fQiVmF86b86BgaWE+RbJEUw3I5JvSDTD2GWTHjIL5O7\n" +
            "ry68YofiurIpZdfIFReYU0Gt9jpXetc/MWDrwMQ=\n" +
            "-----END CERTIFICATE-----\n";

    @Before
    public void setUp() {

        this.psd2Collector = PSD2Collector.psd2Builder()
                .collectorName("psd2-for-test")
                .usernameCollector(certificatesChain -> certificatesChain[0].getSubjectDN().getName())
                .authoritiesCollector((certificatesChain, psd2CertInfo, roles) -> {
                    if (roles == null) {
                        return Collections.EMPTY_SET;
                    }
                    return roles.getRolesOfPsp().stream().map(r -> new PSD2GrantType(r)).collect(Collectors.toSet());
                })
                .collectFromHeader(CertificateHeaderFormat.PEM)
                .headerName(headerName)
                .build();
    }

    @Test
    public void testAuthentication() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader(headerName)).thenReturn(testPSD2Certificate);

        //When
        Authentication authentication = psd2Collector.collectAuthentication(mockedRequest);

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("CN=0015800001HQQrpAAH, OID.2.5.4.97=PSDGB-TEST-123456, O=Test Bank PLC, C=GB")
                .password("")
                .authorities(Collections.emptySet())
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();
        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
    }

    @Test
    public void testAuthorisation() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader(headerName)).thenReturn(testPSD2Certificate);

        ScopeGrantType accountsScope = new ScopeGrantType("accounts");

        //When
        Authentication authentication = psd2Collector.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(accountsScope)));

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(new PSD2GrantType(new RoleOfPsp(Psd2Role.PSP_AI)), accountsScope).collect(Collectors.toSet()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test
    public void testNonPSD2CertAuthentication() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader(headerName)).thenReturn(testNonPSD2Cert);

        //When
        Authentication authentication = psd2Collector.collectAuthentication(mockedRequest);

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("CN=*.bluehost.com, OU=PositiveSSL Wildcard, OU=\"Hosted by BlueHost.Com, INC\", OU=Domain Control Validated")
                .password("")
                .authorities(Collections.emptySet())
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();
        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
    }
}