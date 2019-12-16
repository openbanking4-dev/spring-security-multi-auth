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
package dev.openbanking4.spring.security.multiauth.model.authentication;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.Data;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Data
public class JwtAuthentication extends AbstractAuthenticationToken implements AuthenticationWithEditableAuthorities {

    private User principal;
    private JWTClaimsSet jwtClaimsSet;

    public JwtAuthentication(String username, Collection<? extends GrantedAuthority> authorities, JWTClaimsSet jwtClaimsSet) {
        super(authorities);
        this.principal =  new User(username, "", authorities);
        this.jwtClaimsSet = jwtClaimsSet;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public AuthenticationWithEditableAuthorities addAuthorities(Collection<GrantedAuthority> authorities) {
        Set<GrantedAuthority> concat = new HashSet<>();
        concat.addAll(authorities);
        concat.addAll(principal.getAuthorities());
        JwtAuthentication passwordLessUserNameAuthentication = new JwtAuthentication(principal.getUsername(), concat, jwtClaimsSet);
        passwordLessUserNameAuthentication.setAuthenticated(this.isAuthenticated());
        return passwordLessUserNameAuthentication;
    }
}
