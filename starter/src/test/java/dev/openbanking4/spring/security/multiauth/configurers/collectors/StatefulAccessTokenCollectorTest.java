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
import dev.openbanking4.spring.security.multiauth.model.granttypes.CustomGrantType;
import dev.openbanking4.spring.security.multiauth.model.granttypes.ScopeGrantType;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class StatefulAccessTokenCollectorTest {

    private StatefulAccessTokenCollector statefulAccessTokenCollector;

    @Before
    public void setUp() {
        this.statefulAccessTokenCollector = StatefulAccessTokenCollector.builder()
                .collectorName("stateful-access-token-for-test")
                .tokenValidator(token -> token)
                .authoritiesCollector(token -> Stream.of(CustomGrantType.INTERNAL, new ScopeGrantType("accounts"),
                        new ScopeGrantType("payments")).collect(Collectors.toSet()))
                .build();
    }

    @Test
    public void testAuthorisation() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader("Authorization")).thenReturn("Bearer JhY2NvdW50cyIsInBheW1");

        //When
        Authentication authentication = statefulAccessTokenCollector.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(CustomGrantType.INTERNAL)));

        //Then
        assertThat(authentication).isNotNull();
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(CustomGrantType.INTERNAL, new ScopeGrantType("accounts"),
                        new ScopeGrantType("payments")).collect(Collectors.toSet()))
                .build();
        UserDetails userDetailsResult = (UserDetails) authentication.getPrincipal();

        assertThat(userDetailsResult.getUsername()).isEqualTo(userDetailsExpected.getUsername());
        assertThat(userDetailsResult.getAuthorities()).isEqualTo(userDetailsExpected.getAuthorities());
    }

    @Test(expected = BadCredentialsException.class)
    public void testWrongAccessToken() {
        //Given
        HttpServletRequest mockedRequest = Mockito.mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletWebRequest(mockedRequest));

        when(mockedRequest.getHeader("Authorization")).thenReturn("Bearer wrwerwOUPPS");
        StatefulAccessTokenCollector statefulAccessTokenCollectorReturn401 = StatefulAccessTokenCollector.builder()
                        .collectorName("statefull-access-token-for-test")
                        .tokenValidator(token -> token)
                        .authoritiesCollector(token -> {
                            throw new HttpClientErrorException(HttpStatus.FORBIDDEN, "Wrong token");
                        })
                        .build();

        //When
        statefulAccessTokenCollectorReturn401.collectAuthorisation(
                mockedRequest,
                new PasswordLessUserNameAuthentication("toto", Collections.singleton(CustomGrantType.INTERNAL)));

        //Then BadCredentialsException
    }
}