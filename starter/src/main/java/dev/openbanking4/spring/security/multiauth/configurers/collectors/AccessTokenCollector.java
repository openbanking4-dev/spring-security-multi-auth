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

import com.nimbusds.jose.JOSEException;
import dev.openbanking4.spring.security.multiauth.configurers.AuthCollector;
import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;
import java.util.Set;

@Slf4j
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Data
public abstract class AccessTokenCollector<T> implements AuthCollector {

    protected TokenValidator<T> tokenValidator;
    protected AuthoritiesCollector<T> authoritiesCollector;
    protected String collectorName = this.getClass().getName();

    @Override
    public String collectorName() {
        return collectorName;
    }
    @Override
    public Authentication collectAuthentication(HttpServletRequest request) {
        return null;
    }

    @Override
    public Authentication collectAuthorisation(HttpServletRequest req, Authentication currentAuthentication) {
        log.trace("Looking for bearer token");
        String authorization = req.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String tokenSerialised = authorization.replaceFirst("Bearer ", "");
            log.trace("Token received {}", tokenSerialised);
            try {
                T t = getTokenValidator().validate(tokenSerialised);
                Set<GrantedAuthority> authorities = getAuthoritiesCollector().getAuthorities(t);
                log.trace("Authorities founds: {}", authorities);

                authorities.addAll(currentAuthentication.getAuthorities());
                log.trace("Final authorities merged with previous authorities: {}", authorities);

                PasswordLessUserNameAuthentication passwordLessUserNameAuthentication = new PasswordLessUserNameAuthentication(currentAuthentication.getName(), authorities);
                passwordLessUserNameAuthentication.setAuthenticated(currentAuthentication.isAuthenticated());
                return passwordLessUserNameAuthentication;
            } catch (HttpClientErrorException e) {
                log.trace("Access token not valid", e);
                if (e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.FORBIDDEN) {
                    throw new BadCredentialsException("Invalid access token", e);
                }
                throw e;
            } catch (ParseException e) {
                log.trace("Couldn't parse the access token", e);
                throw new BadCredentialsException("Invalid access token", e);
            } catch (JOSEException e) {
                log.trace("Couldn't parse the access token", e);
                throw new BadCredentialsException("Invalid access token", e);
            }
        } else {
            log.trace("No access token found");
        }
        return currentAuthentication;
    }


    public interface TokenValidator<T> {
        T validate(String tokenSerialised) throws ParseException, JOSEException;
    }

    public interface UsernameCollector<T> {
        String getUserName(T token) throws ParseException;
    }

    public interface AuthoritiesCollector<T> {
        Set<GrantedAuthority> getAuthorities(T token) throws ParseException;
    }
}
