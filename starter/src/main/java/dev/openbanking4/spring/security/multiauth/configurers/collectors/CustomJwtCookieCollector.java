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

import com.nimbusds.jwt.JWT;
import dev.openbanking4.spring.security.multiauth.model.authentication.AuthenticationWithEditableAuthorities;
import dev.openbanking4.spring.security.multiauth.model.authentication.JwtAuthentication;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.Collections;

@Slf4j
@ToString
@Getter
public class CustomJwtCookieCollector extends CustomCookieCollector<JWT> {

    @Builder
    public CustomJwtCookieCollector(String collectorName, TokenValidator<JWT> tokenValidator, AuthoritiesCollector<JWT> authoritiesCollector, String cookieName) {
        super(
                collectorName,
                tokenValidator,
                token -> token.getJWTClaimsSet().getSubject(),
                authoritiesCollector,
                cookieName
        );
    }

    @Override
    protected AuthenticationWithEditableAuthorities createAuthenticationUser(String username, JWT token) {
        try {
            return new JwtAuthentication(username, Collections.EMPTY_SET, token.getJWTClaimsSet());
        } catch (ParseException e) {
            log.warn("Couldn't read the claims of the jwt token. username: {} and token: {}", username, token.serialize());
            return new JwtAuthentication(username, Collections.EMPTY_SET, null);
        }
    }
}
