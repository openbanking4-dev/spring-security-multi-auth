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


import com.nimbusds.jwt.JWTParser;
import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import dev.openbanking4.spring.security.multiauth.model.granttypes.ScopeGrantType;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CustomJwtCookieCollectorTest {

    private CustomCookieCollector customCookieCollector;

    @Before
    public void setUp() {

        this.customCookieCollector = CustomJwtCookieCollector.builder()
                .collectorName("Custom-cookie-jwt-for-test")
                .authoritiesCollector(token -> token.getJWTClaimsSet().getStringListClaim("group").stream()
                                                .map(g -> new SimpleGrantedAuthority(g)).collect(Collectors.toSet()))
                .tokenValidator(tokenSerialised -> JWTParser.parse(tokenSerialised))
                .cookieName("sso")
                .build();
    }

    @Test
    public void testAuthentication() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("sso",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbEtpbmciXX0.3JsO3h2HEZSJy4sX45RfKfwzPIWvdgt1LbHeEjExWZY")});

        //When
        Authentication authentication = customCookieCollector.collectAuthentication(mockedRequest);

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
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

        when(mockedRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("sso",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbEtpbmciXX0.3JsO3h2HEZSJy4sX45RfKfwzPIWvdgt1LbHeEjExWZY")});

        ScopeGrantType accountsScope = new ScopeGrantType("accounts");

        //When
        Authentication authentication = customCookieCollector.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(accountsScope)));

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(new SimpleGrantedAuthority("admin"), new SimpleGrantedAuthority("clubFalafelKing"), accountsScope).collect(Collectors.toSet()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test(expected = BadCredentialsException.class)
    public void testWrongCookie() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("sso",
                "oups")});

        //When
        customCookieCollector.collectAuthentication(mockedRequest);

        //Then BadCredentialsException
    }

    @Test(expected = BadCredentialsException.class)
    public void test401On0CookieValidationByExternalParty() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("sso",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbEtpbmciXX0.3JsO3h2HEZSJy4sX45RfKfwzPIWvdgt1LbHeEjExWZY")});

        CustomJwtCookieCollector customCookieCollector401 =
                CustomJwtCookieCollector.builder()
                        .collectorName("Custom-cookie-jwt-for-test")
                        .authoritiesCollector(token -> {
                            throw new HttpClientErrorException(HttpStatus.FORBIDDEN, "Wrong token");
                        })
                        .tokenValidator(token -> {
                            throw new HttpClientErrorException(HttpStatus.FORBIDDEN, "Wrong token");
                        })
                        .cookieName("sso")
                        .build();;

        //When
        customCookieCollector401.collectAuthentication(mockedRequest);

        //Then BadCredentialsException
    }
}