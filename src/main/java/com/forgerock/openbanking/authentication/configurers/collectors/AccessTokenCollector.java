package com.forgerock.openbanking.authentication.configurers.collectors;

import com.forgerock.openbanking.authentication.configurers.AuthCollector;
import com.forgerock.openbanking.authentication.configurers.PasswordLessUserNameAuthentication;
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
                Object userName = currentAuthentication.getPrincipal();
                Set<GrantedAuthority> authorities = getAuthoritiesCollector().getAuthorities(t);
                authorities.addAll(currentAuthentication.getAuthorities());
                return new PasswordLessUserNameAuthentication(userName, authorities);
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
