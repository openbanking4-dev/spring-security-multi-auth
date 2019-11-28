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

    @Override
    public Authentication collectAuthentication(HttpServletRequest request) {
        return new PasswordLessUserNameAuthentication(usernameCollector.getUserName(), Collections.EMPTY_SET);
    }

    @Override
    public Authentication collectAuthorisation(HttpServletRequest request, Authentication currentAuthentication) {

        Set<GrantedAuthority> authorities = new HashSet<>(grantedAuthorities);
        authorities.addAll(currentAuthentication.getAuthorities());

        PasswordLessUserNameAuthentication passwordLessUserNameAuthentication = new PasswordLessUserNameAuthentication(currentAuthentication.getName(), authorities);
        passwordLessUserNameAuthentication.setAuthenticated(currentAuthentication.isAuthenticated());
        return passwordLessUserNameAuthentication;
    }

    public interface UsernameCollector {
        String getUserName();
    }

}
