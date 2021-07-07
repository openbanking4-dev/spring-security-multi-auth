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

import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.client.HttpClientErrorException;

import com.nimbusds.jose.JOSEException;

import dev.openbanking4.spring.security.multiauth.configurers.AuthCollector;
import dev.openbanking4.spring.security.multiauth.model.authentication.AuthenticationWithEditableAuthorities;
import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import dev.openbanking4.spring.security.multiauth.model.authentication.UserWithPasswordAuthentication;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@ToString
@AllArgsConstructor
@Builder
public class BasicAuthCollector implements AuthCollector {

    protected CredentialValidator credentialValidator;
    protected AuthoritiesCollector authoritiesCollector;

    protected String collectorName = this.getClass().getName();
    private static final Base64.Decoder base64Decoder = Base64.getDecoder();

    @Override
    public String collectorName() {
        return collectorName;
    }

    @Override
    public AuthenticationWithEditableAuthorities collectAuthentication(HttpServletRequest req) {
        String authorization = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Basic ")) {
            log.trace("Basic authorization found {}", authorization);
            String basicAuthEncoded = authorization.replaceFirst("Basic ", "");
            String basicAuthDecoded = new String(base64Decoder.decode(basicAuthEncoded));
            String[] basicAuthSplit = basicAuthDecoded.split(":");
            String username = basicAuthSplit[0];
            String password = basicAuthSplit[1];
            try {
                if (credentialValidator.validate(username, password)) {
                    return new UserWithPasswordAuthentication(username, password, Collections.EMPTY_SET);
                } else {
                    log.trace("Credential validation failed");
                }
            } catch (HttpClientErrorException e) {
                log.trace("API key not valid", e);
                if (e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.FORBIDDEN) {
                    throw new BadCredentialsException("Invalid API key", e);
                }
                throw e;
            }
        } else {
            log.trace("No basic auth found");
        }
        return null;
    }

    @Override
    public AuthenticationWithEditableAuthorities collectAuthorisation(HttpServletRequest req, AuthenticationWithEditableAuthorities currentAuthentication) {
        String authorization = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Basic ")) {
            log.trace("Basic authorization found {}", authorization);
            String basicAuthEncoded = authorization.replaceFirst("Basic ", "");
            String basicAuthDecoded = new String(base64Decoder.decode(basicAuthEncoded));
            String[] basicAuthSplit = basicAuthDecoded.split(":");
            String username = basicAuthSplit[0];
            try {
                Set<GrantedAuthority> authorities = authoritiesCollector.getAuthorities(username);
                log.trace("Authorities founds: {}", authorities);

                authorities.addAll(currentAuthentication.getAuthorities());
                log.trace("Final authorities merged with previous authorities: {}", authorities);

                return currentAuthentication.addAuthorities(authorities);
            } catch (HttpClientErrorException e) {
                log.trace("Credentials from basic auth are not valid", e);
                if (e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.FORBIDDEN) {
                    throw new BadCredentialsException("Invalid basic auth credentials", e);
                }
                throw e;
            }
        } else {
            log.trace("No basic auth found");
        }
        return currentAuthentication;
    }

    @Override
    public boolean isSetupForAuthentication() {
        return credentialValidator != null;
    }

    @Override
    public boolean isSetupForAuthorisation() {
        return authoritiesCollector != null;
    }

    public interface CredentialValidator {
        Boolean validate(String username, String password);
    }

    public interface AuthoritiesCollector {
        Set<GrantedAuthority> getAuthorities(String username);
    }
}
