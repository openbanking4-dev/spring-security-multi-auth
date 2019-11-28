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
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@ToString
@AllArgsConstructor
@Data
public abstract class CustomCookieCollector<T> implements AuthCollector {

    protected TokenValidator<T> tokenValidator;
    protected UsernameCollector<T> usernameCollector;
    protected AuthoritiesCollector<T> authoritiesCollector;
    protected String cookieName;

    @Override
    public Authentication collectAuthentication(HttpServletRequest request) {
        log.trace("Looking for cookies");
        Cookie cookie = getCookie(request, cookieName);
        if (cookie != null) {
            String tokenSerialised = cookie.getValue();
            log.trace("Token received", tokenSerialised);
            try {
                T t = getTokenValidator().validate(tokenSerialised);
                String userName = getUsernameCollector().getUserName(t);
                return new PasswordLessUserNameAuthentication(userName, Collections.EMPTY_SET);
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
        return null;
    }

    @Override
    public Authentication collectAuthorisation(HttpServletRequest request, Authentication currentAuthentication) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        Cookie cookie = getCookie(request, cookieName);
        if (cookie != null) {
            String tokenSerialised = cookie.getValue();
            log.trace("Token received", tokenSerialised);
            try {
                T t = getTokenValidator().validate(tokenSerialised);
                authorities.addAll(authoritiesCollector.getAuthorities(t));
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
        authorities.addAll(currentAuthentication.getAuthorities());
        PasswordLessUserNameAuthentication passwordLessUserNameAuthentication = new PasswordLessUserNameAuthentication(currentAuthentication.getName(), authorities);
        passwordLessUserNameAuthentication.setAuthenticated(currentAuthentication.isAuthenticated());
        return passwordLessUserNameAuthentication;
    }

    private Cookie getCookie(HttpServletRequest request, String name) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(name)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    public interface TokenValidator<T> {
        T validate(String tokenSerialised) throws ParseException;
    }

    public interface UsernameCollector<T> {
        String getUserName(T token) throws ParseException;
    }

    public interface AuthoritiesCollector<T> {
        Set<GrantedAuthority> getAuthorities(T token);
    }
}
