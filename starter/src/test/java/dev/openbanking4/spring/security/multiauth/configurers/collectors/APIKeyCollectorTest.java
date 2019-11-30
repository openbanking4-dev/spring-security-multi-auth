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

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class APIKeyCollectorTest {

    private APIKeyCollector<User> apiKeyCollector;

    @Before
    public void setUp() {

        this.apiKeyCollector = APIKeyCollector.<User>builder()
                .collectorName("API-key-for-test")
                .apiKeyExtractor(req -> req.getParameter("key"))
                .apiKeyValidator(apiKey -> new User("toto", "",
                        Stream.of(new SimpleGrantedAuthority("repo-32")).collect(Collectors.toSet())))
                .authoritiesCollector(user -> new HashSet<>(user.getAuthorities()))
                .usernameCollector(User::getUsername)
                .build();
    }

    @Test
    public void testAuthentication() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getParameter("key")).thenReturn("9wZSI6WyJhY2Nvd");

        //When
        Authentication authentication = apiKeyCollector.collectAuthentication(mockedRequest);

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

        when(mockedRequest.getParameter("key")).thenReturn("9wZSI6WyJhY2Nvd");

        ScopeGrantType accountsScope = new ScopeGrantType("accounts");

        //When
        Authentication authentication = apiKeyCollector.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(accountsScope)));

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(new SimpleGrantedAuthority("repo-32"), accountsScope).collect(Collectors.toSet()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }


    @Test(expected = BadCredentialsException.class)
    public void test401On0CookieValidationByExternalPartyForAuthentication() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getParameter("key")).thenReturn("9wZSI6WyJhY2Nvd");

        APIKeyCollector apiKeyCollector401 =
                APIKeyCollector.<User>builder()
                        .collectorName("API-key-for-test")
                        .apiKeyExtractor(req -> req.getParameter("key"))
                        .apiKeyValidator(apiKey -> {
                            throw new HttpClientErrorException(HttpStatus.FORBIDDEN, "Wrong token");
                        })
                        .authoritiesCollector(user -> new HashSet<>(user.getAuthorities()))
                        .usernameCollector(User::getUsername)
                        .build();;

        //When
        apiKeyCollector401.collectAuthentication(mockedRequest);

        //Then BadCredentialsException
    }

    @Test(expected = BadCredentialsException.class)
    public void test401On0CookieValidationByExternalPartyForAuthorisation() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getParameter("key")).thenReturn("9wZSI6WyJhY2Nvd");

        APIKeyCollector apiKeyCollector401 =
                APIKeyCollector.<User>builder()
                        .collectorName("API-key-for-test")
                        .apiKeyExtractor(req -> req.getParameter("key"))
                        .apiKeyValidator(apiKey -> {
                            throw new HttpClientErrorException(HttpStatus.FORBIDDEN, "Wrong token");
                        })
                        .authoritiesCollector(user -> new HashSet<>(user.getAuthorities()))
                        .usernameCollector(User::getUsername)
                        .build();;

        ScopeGrantType accountsScope = new ScopeGrantType("accounts");

        //When
        apiKeyCollector401.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(accountsScope)));

        //Then BadCredentialsException
    }
}