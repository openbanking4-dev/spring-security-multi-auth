/*
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