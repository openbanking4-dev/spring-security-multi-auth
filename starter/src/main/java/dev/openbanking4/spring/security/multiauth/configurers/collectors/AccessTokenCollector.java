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
            log.trace("Token received", tokenSerialised);
            try {
                T t = getTokenValidator().validate(tokenSerialised);
                Set<GrantedAuthority> authorities = getAuthoritiesCollector().getAuthorities(t);
                authorities.addAll(currentAuthentication.getAuthorities());

                PasswordLessUserNameAuthentication passwordLessUserNameAuthentication = new PasswordLessUserNameAuthentication(currentAuthentication.getName(), authorities);
                passwordLessUserNameAuthentication.setAuthenticated(currentAuthentication.isAuthenticated());
                return passwordLessUserNameAuthentication;

            } catch (HttpClientErrorException e) {
                if (e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.FORBIDDEN) {
                    throw new BadCredentialsException("Invalid cookie");
                }
                throw e;
            } catch (ParseException e) {
                e.printStackTrace();
            }
        } else {
            log.trace("No cookie found");
        }
        return currentAuthentication;
    }


    public interface TokenValidator<T> {
        T validate(String tokenSerialised) throws ParseException;
    }

    public interface UsernameCollector<T> {
        String getUserName(T token) throws ParseException;
    }

    public interface AuthoritiesCollector<T> {
        Set<GrantedAuthority> getAuthorities(T token) throws ParseException;
    }
}
