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
package dev.openbanking4.spring.security.multiauth.configurers;

import com.forgerock.cert.psd2.Psd2Role;
import com.forgerock.cert.psd2.RoleOfPsp;
import com.nimbusds.jwt.JWTParser;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.CustomJwtCookieCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.PSD2Collector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StatelessAccessTokenCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StaticUserCollector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.granttypes.PSD2GrantType;
import dev.openbanking4.spring.security.multiauth.model.granttypes.ScopeGrantType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class AuthCollectorFilterTest {
    private String testCertificate =  "-----BEGIN CERTIFICATE-----\n" +
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

    private StaticUserCollector staticUserCollector = new StaticUserCollector(
            () -> "bob", Stream.of(new SimpleGrantedAuthority("bobPower")).collect(Collectors.toSet()));

    private CustomJwtCookieCollector customJwtCookieCollector = new CustomJwtCookieCollector(
            tokenSerialised -> JWTParser.parse(tokenSerialised),
            token -> {
                try {
                    return token.getJWTClaimsSet().getStringListClaim("group").stream()
                            .map(g -> new SimpleGrantedAuthority(g)).collect(Collectors.toSet());
                } catch (ParseException e) {
                    return Collections.EMPTY_SET;
                }
            },
            "sso");

    private PSD2Collector psd2Collector = new PSD2Collector(
            certificatesChain -> certificatesChain[0].getSubjectDN().getName(),
            (certificatesChain, psd2CertInfo, roles) -> {
                if (roles == null) {
                    return Collections.EMPTY_SET;
                }
                return roles.getRolesOfPsp().stream().map(r -> new PSD2GrantType(r)).collect(Collectors.toSet());
            },
            CertificateHeaderFormat.PEM,
            "x-cert");

    private StatelessAccessTokenCollector statelessAccessTokenCollector =  new StatelessAccessTokenCollector(
            token -> JWTParser.parse(token)
            );

    @Test
    public void testStaticUser() throws Exception {
        //Given
        SecurityContextHolder.getContext().setAuthentication(null);
        List<AuthCollector> authCollectors = Stream.of(
                customJwtCookieCollector,
                psd2Collector,
                statelessAccessTokenCollector,
                staticUserCollector
        ).collect(Collectors.toList());
        AuthCollectorFilter authCollectorFilter = new AuthCollectorFilter(authCollectors, authCollectors);

        //When
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        authCollectorFilter.doFilterInternal(mockedRequest, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        //Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();

        UserDetails userDetailsExpected = User.builder()
                .username("bob")
                .password("")
                .authorities(Collections.singleton(new SimpleGrantedAuthority("bobPower")))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test
    public void testCookie() throws Exception {
        //Given
        SecurityContextHolder.getContext().setAuthentication(null);
        List<AuthCollector> authCollectors = Stream.of(
                customJwtCookieCollector,
                psd2Collector,
                statelessAccessTokenCollector,
                staticUserCollector
        ).collect(Collectors.toList());
        AuthCollectorFilter authCollectorFilter = new AuthCollectorFilter(authCollectors, authCollectors);

        //When
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("sso",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbCJdfQ.kQDyIfKsf7xM0uN2F47X_yJgtgnG8CDYtPc6t5KAHL8")});

        authCollectorFilter.doFilterInternal(mockedRequest, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        //Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();

        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(
                        new SimpleGrantedAuthority("admin"),
                        new SimpleGrantedAuthority("clubFalafel"),
                        new SimpleGrantedAuthority("bobPower")
                ).collect(Collectors.toList()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test
    public void testCookieAndAccessToken() throws Exception {
        //Given
        SecurityContextHolder.getContext().setAuthentication(null);
        List<AuthCollector> authCollectors = Stream.of(
                customJwtCookieCollector,
                psd2Collector,
                statelessAccessTokenCollector,
                staticUserCollector
        ).collect(Collectors.toList());
        AuthCollectorFilter authCollectorFilter = new AuthCollectorFilter(authCollectors, authCollectors);

        //When
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("sso",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbCJdfQ.kQDyIfKsf7xM0uN2F47X_yJgtgnG8CDYtPc6t5KAHL8")});
        when(mockedRequest.getHeader("Authorization")).thenReturn(
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl19.NpzyDWjuoC9oAE50fb3W2Mgs1ORWuWYCMv2xg677fGc");


        authCollectorFilter.doFilterInternal(mockedRequest, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        //Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();

        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(
                        new SimpleGrantedAuthority("admin"),
                        new SimpleGrantedAuthority("clubFalafel"),
                        new SimpleGrantedAuthority("bobPower"),
                        new ScopeGrantType("accounts"),
                        new ScopeGrantType("payments")
                ).collect(Collectors.toList()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test
    public void testCertificatesAndAccessToken() throws Exception {
        //Given
        SecurityContextHolder.getContext().setAuthentication(null);
        List<AuthCollector> authCollectors = Stream.of(
                customJwtCookieCollector,
                psd2Collector,
                statelessAccessTokenCollector,
                staticUserCollector
        ).collect(Collectors.toList());
        AuthCollectorFilter authCollectorFilter = new AuthCollectorFilter(authCollectors, authCollectors);

        //When
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader("x-cert")).thenReturn(testCertificate);
        when(mockedRequest.getHeader("Authorization")).thenReturn(
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl19.NpzyDWjuoC9oAE50fb3W2Mgs1ORWuWYCMv2xg677fGc");


        authCollectorFilter.doFilterInternal(mockedRequest, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        //Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();

        UserDetails userDetailsExpected = User.builder()
                .username("CN=0015800001HQQrpAAH, OID.2.5.4.97=PSDGB-TEST-123456, O=Test Bank PLC, C=GB")
                .password("")
                .authorities(Stream.of(
                        new PSD2GrantType(new RoleOfPsp(Psd2Role.PSP_AI)),
                        new SimpleGrantedAuthority("bobPower"),
                        new ScopeGrantType("accounts"),
                        new ScopeGrantType("payments")
                ).collect(Collectors.toList()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test
    public void testAuthenticationOrder() throws Exception {
        //Given
        SecurityContextHolder.getContext().setAuthentication(null);
        List<AuthCollector> authCollectors = Stream.of(
                customJwtCookieCollector,
                psd2Collector,
                statelessAccessTokenCollector,
                staticUserCollector
        ).collect(Collectors.toList());
        AuthCollectorFilter authCollectorFilter = new AuthCollectorFilter(authCollectors, authCollectors);

        //When
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader("x-cert")).thenReturn(testCertificate);
        when(mockedRequest.getHeader("Authorization")).thenReturn(
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl19.NpzyDWjuoC9oAE50fb3W2Mgs1ORWuWYCMv2xg677fGc");
        when(mockedRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("sso",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbCJdfQ.kQDyIfKsf7xM0uN2F47X_yJgtgnG8CDYtPc6t5KAHL8")});


        authCollectorFilter.doFilterInternal(mockedRequest, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        //Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();

        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(
                        new PSD2GrantType(new RoleOfPsp(Psd2Role.PSP_AI)),
                        new SimpleGrantedAuthority("admin"),
                        new SimpleGrantedAuthority("clubFalafel"),
                        new SimpleGrantedAuthority("bobPower"),
                        new ScopeGrantType("accounts"),
                        new ScopeGrantType("payments")
                ).collect(Collectors.toList()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test
    public void testAuthenticationDiffOrder() throws Exception {
        //Given
        SecurityContextHolder.getContext().setAuthentication(null);
        List<AuthCollector> authCollectors = Stream.of(
                psd2Collector,
                customJwtCookieCollector,
                statelessAccessTokenCollector,
                staticUserCollector
        ).collect(Collectors.toList());
        AuthCollectorFilter authCollectorFilter = new AuthCollectorFilter(authCollectors, authCollectors);

        //When
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader("x-cert")).thenReturn(testCertificate);
        when(mockedRequest.getHeader("Authorization")).thenReturn(
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl19.NpzyDWjuoC9oAE50fb3W2Mgs1ORWuWYCMv2xg677fGc");
        when(mockedRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("sso",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbCJdfQ.kQDyIfKsf7xM0uN2F47X_yJgtgnG8CDYtPc6t5KAHL8")});


        authCollectorFilter.doFilterInternal(mockedRequest, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        //Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();

        UserDetails userDetailsExpected = User.builder()
                .username("CN=0015800001HQQrpAAH, OID.2.5.4.97=PSDGB-TEST-123456, O=Test Bank PLC, C=GB")
                .password("")
                .authorities(Stream.of(
                        new PSD2GrantType(new RoleOfPsp(Psd2Role.PSP_AI)),
                        new SimpleGrantedAuthority("admin"),
                        new SimpleGrantedAuthority("clubFalafel"),
                        new SimpleGrantedAuthority("bobPower"),
                        new ScopeGrantType("accounts"),
                        new ScopeGrantType("payments")
                ).collect(Collectors.toList()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test
    public void testDiffAuthenticationsAndAuthorisationCollectors() throws Exception {
        //Given
        SecurityContextHolder.getContext().setAuthentication(null);
        List<AuthCollector> authenticationsCollectors = Stream.of(
                psd2Collector
        ).collect(Collectors.toList());
        List<AuthCollector> authorisationsCollectors = Stream.of(
                statelessAccessTokenCollector
        ).collect(Collectors.toList());
        AuthCollectorFilter authCollectorFilter = new AuthCollectorFilter(authenticationsCollectors, authorisationsCollectors);

        //When
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader("x-cert")).thenReturn(testCertificate);
        when(mockedRequest.getHeader("Authorization")).thenReturn(
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl19.NpzyDWjuoC9oAE50fb3W2Mgs1ORWuWYCMv2xg677fGc");

        authCollectorFilter.doFilterInternal(mockedRequest, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        //Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();

        UserDetails userDetailsExpected = User.builder()
                .username("CN=0015800001HQQrpAAH, OID.2.5.4.97=PSDGB-TEST-123456, O=Test Bank PLC, C=GB")
                .password("")
                .authorities(Stream.of(
                        new ScopeGrantType("accounts"),
                        new ScopeGrantType("payments")
                ).collect(Collectors.toList()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test
    public void testNoAuthenticationFound() throws Exception {
        //Given
        SecurityContextHolder.getContext().setAuthentication(null);
        List<AuthCollector> authCollectors = Stream.of(
                psd2Collector,
                customJwtCookieCollector,
                statelessAccessTokenCollector
        ).collect(Collectors.toList());
        AuthCollectorFilter authCollectorFilter = new AuthCollectorFilter(authCollectors, authCollectors);

        //When
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        authCollectorFilter.doFilterInternal(mockedRequest, Mockito.mock(HttpServletResponse.class), Mockito.mock(FilterChain.class));

        //Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull();
    }
}