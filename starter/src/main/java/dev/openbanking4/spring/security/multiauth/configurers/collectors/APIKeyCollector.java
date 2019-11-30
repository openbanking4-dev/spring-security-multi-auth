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

import com.nimbusds.jose.JOSEException;
import dev.openbanking4.spring.security.multiauth.configurers.AuthCollector;
import dev.openbanking4.spring.security.multiauth.model.authentication.PasswordLessUserNameAuthentication;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;
import java.util.Collections;
import java.util.Set;

@Slf4j
@ToString
@AllArgsConstructor
@Builder
public class APIKeyCollector<U> implements AuthCollector {

    protected APIKeyValidator<U> apiKeyValidator;
    protected AuthoritiesCollector<U> authoritiesCollector;
    protected UsernameCollector<U> usernameCollector;
    protected APIKeyExtractor apiKeyExtractor;
    protected String collectorName = this.getClass().getName();

    @Override
    public String collectorName() {
        return collectorName;
    }

    @Override
    public Authentication collectAuthentication(HttpServletRequest req) {
        String apiKey = apiKeyExtractor.fromRequest(req);
        if (apiKey != null) {
            log.trace("API key found {}", apiKey);
            try {
                U user = apiKeyValidator.validate(apiKey);
                log.trace("API key valid", apiKey);
                String userName = usernameCollector.getUserName(user);
                log.trace("Username {} found", userName);
                return new PasswordLessUserNameAuthentication(userName, Collections.EMPTY_SET);
            } catch (HttpClientErrorException e) {
                log.trace("API key not valid", e);
                if (e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.FORBIDDEN) {
                    throw new BadCredentialsException("Invalid API key", e);
                }
                throw e;
            } catch (ParseException e) {
                log.trace("Couldn't parse the API key", e);
                throw new BadCredentialsException("Invalid API key", e);
            } catch (JOSEException e) {
                log.trace("Couldn't parse the API key", e);
                throw new BadCredentialsException("Invalid API key", e);
            }
        } else {
            log.trace("No API key found");
        }
        return null;
    }

    @Override
    public Authentication collectAuthorisation(HttpServletRequest req, Authentication currentAuthentication) {
        log.trace("Looking for API key");
        String apiKey = apiKeyExtractor.fromRequest(req);
        if (apiKey != null) {
            log.trace("Token received {}", apiKey);
            try {
                U user = apiKeyValidator.validate(apiKey);
                Set<GrantedAuthority> authorities = authoritiesCollector.getAuthorities(user);
                log.trace("Authorities founds: {}", authorities);

                authorities.addAll(currentAuthentication.getAuthorities());
                log.trace("Final authorities merged with previous authorities: {}", authorities);

                PasswordLessUserNameAuthentication passwordLessUserNameAuthentication = new PasswordLessUserNameAuthentication(currentAuthentication.getName(), authorities);
                passwordLessUserNameAuthentication.setAuthenticated(currentAuthentication.isAuthenticated());
                return passwordLessUserNameAuthentication;
            } catch (HttpClientErrorException e) {
                log.trace("API key not valid", e);
                if (e.getStatusCode() == HttpStatus.UNAUTHORIZED || e.getStatusCode() == HttpStatus.FORBIDDEN) {
                    throw new BadCredentialsException("Invalid API key", e);
                }
                throw e;
            } catch (ParseException e) {
                log.trace("Couldn't parse the API key", e);
                throw new BadCredentialsException("Invalid API key", e);
            } catch (JOSEException e) {
                log.trace("Couldn't parse the API key", e);
                throw new BadCredentialsException("Invalid API key", e);
            }
        } else {
            log.trace("No API key found");
        }
        return currentAuthentication;
    }

    public interface APIKeyValidator<U> {
        U validate(String apiKey) throws ParseException, JOSEException;
    }

    public interface UsernameCollector<U> {
        String getUserName(U user) throws ParseException;
    }

    public interface AuthoritiesCollector<U> {
        Set<GrantedAuthority> getAuthorities(U user) throws ParseException;
    }

    public interface APIKeyExtractor {
        String fromRequest(HttpServletRequest req);
    }
}
