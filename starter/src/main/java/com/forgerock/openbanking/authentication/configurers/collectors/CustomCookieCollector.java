package com.forgerock.openbanking.authentication.configurers.collectors;

import com.forgerock.openbanking.authentication.configurers.AuthCollector;
import com.forgerock.openbanking.authentication.model.authentication.PasswordLessUserNameAuthentication;
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
    public Authentication collectAuthorisation(HttpServletRequest req, Authentication currentAuthentication) {
        return currentAuthentication;
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
