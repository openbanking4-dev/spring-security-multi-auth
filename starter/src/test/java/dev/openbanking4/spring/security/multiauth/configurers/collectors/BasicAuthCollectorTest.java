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


import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletWebRequest;

import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import dev.openbanking4.spring.security.multiauth.model.granttypes.CustomGrantType;
import dev.openbanking4.spring.security.multiauth.model.granttypes.ScopeGrantType;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class BasicAuthCollectorTest {

    private BasicAuthCollector basicAuthCollector;
    private static final Base64.Encoder base64Encoder = Base64.getEncoder();

    @Before
    public void setUp() {

        this.basicAuthCollector = BasicAuthCollector.<User>builder()
                .collectorName("Basic-auth-for-test")
                .credentialValidator((username, password) -> {
                    if (username.equals("toto") && password.equals("changeit")) {
                        return true;
                    }
                    throw new HttpClientErrorException(HttpStatus.FORBIDDEN, "Wrong credential");
                })
                .authoritiesCollector((username) -> Stream.of(CustomGrantType.INTERNAL).collect(Collectors.toSet()))
                .build();
    }

    @Test
    public void testAuthentication() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Basic " + base64Encoder.encodeToString(
                String.format("%s:%s", "toto", "changeit").getBytes(Charset.forName("UTF-8"))));

        //When
        Authentication authentication = basicAuthCollector.collectAuthentication(mockedRequest);

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("changeit")
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

        when(mockedRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Basic " + base64Encoder.encodeToString(
                String.format("%s:%s", "toto", "changeit").getBytes(Charset.forName("UTF-8"))));

        ScopeGrantType accountsScope = new ScopeGrantType("accounts");

        //When
        Authentication authentication = basicAuthCollector.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(accountsScope)));

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("changeit")
                .authorities(Stream.of(CustomGrantType.INTERNAL, accountsScope).collect(Collectors.toSet()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }


    @Test(expected = BadCredentialsException.class)
    public void test401On0BasicAuthValidationByExternalPartyForAuthentication() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Basic " + base64Encoder.encodeToString(
                String.format("%s:%s", "toto", "wrongpassword").getBytes(Charset.forName("UTF-8"))));



        //When
        basicAuthCollector.collectAuthentication(mockedRequest);

        //Then BadCredentialsException
    }
}