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

import dev.openbanking4.spring.security.multiauth.configurers.AuthCollector;
import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Builder
@AllArgsConstructor
public class StaticUserCollector implements AuthCollector {

    private UsernameCollector usernameCollector;
    private Set<GrantedAuthority> grantedAuthorities = Collections.EMPTY_SET;
    private String collectorName = this.getClass().getName();

    @Override
    public String collectorName() {
        return collectorName;
    }

    @Override
    public Authentication collectAuthentication(HttpServletRequest request) {
        return new PasswordLessUserNameAuthentication(usernameCollector.getUserName(), Collections.EMPTY_SET);
    }

    @Override
    public Authentication collectAuthorisation(HttpServletRequest request, Authentication currentAuthentication) {

        Set<GrantedAuthority> authorities = new HashSet<>(grantedAuthorities);
        log.trace("Authorities setup for the static user: {}", authorities);
        authorities.addAll(currentAuthentication.getAuthorities());
        log.trace("Final authorities merged with previous authorities: {}", authorities);

        PasswordLessUserNameAuthentication passwordLessUserNameAuthentication = new PasswordLessUserNameAuthentication(currentAuthentication.getName(), authorities);
        passwordLessUserNameAuthentication.setAuthenticated(currentAuthentication.isAuthenticated());
        return passwordLessUserNameAuthentication;
    }

    public interface UsernameCollector {
        String getUserName();
    }

    @Override
    public boolean isSetupForAuthentication() {
        return usernameCollector != null;
    }

    @Override
    public boolean isSetupForAuthorisation() {
        return true;
    }
}
