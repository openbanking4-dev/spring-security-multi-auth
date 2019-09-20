package com.forgerock.openbanking.authentication.configurers.collectors;

import com.forgerock.openbanking.authentication.configurers.AuthCollector;
import com.forgerock.openbanking.authentication.configurers.PasswordLessUserNameAuthentication;
import com.forgerock.openbanking.authentication.utils.RequestUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

@Slf4j
@AllArgsConstructor
public class X509Collector implements AuthCollector {

    private UsernameCollector usernameCollector;
    private AuthoritiesCollector authoritiesCollector;

    @Override
    public Authentication collectAuthentication(HttpServletRequest request) {


        if (RequestContextHolder.getRequestAttributes() == null) {
            log.warn("No request attributes available!");
            return null;
        }
        if (request == null) {
            log.warn("No request received!");
            return null;
        }

        X509Certificate[] certificatesChain = RequestUtils.extractCertificatesChain(request);

        //Check if no client certificate received
        if (certificatesChain == null || certificatesChain.length == 0) {
            log.debug("No certificate received");
            return null;
        }

        String username = usernameCollector.getUserName(certificatesChain);

        return new PasswordLessUserNameAuthentication(username, Collections.EMPTY_SET);
    }

    @Override
    public Authentication collectAuthorisation(HttpServletRequest request, Authentication currentAuthentication) {

        if (RequestContextHolder.getRequestAttributes() == null) {
            log.warn("No request attributes available!");
            return currentAuthentication;
        }
        if (request == null) {
            log.warn("No request received!");
            return currentAuthentication;
        }

        X509Certificate[] certificatesChain = RequestUtils.extractCertificatesChain(request);

        //Check if no client certificate received
        if (certificatesChain == null || certificatesChain.length == 0) {
            log.debug("No certificate received");
            return currentAuthentication;
        }

        Set<GrantedAuthority> authorities = authoritiesCollector.getAuthorities(certificatesChain);
        authorities.addAll(currentAuthentication.getAuthorities());

        PasswordLessUserNameAuthentication passwordLessUserNameAuthentication = new PasswordLessUserNameAuthentication(currentAuthentication.getName(), authorities);
        passwordLessUserNameAuthentication.setAuthenticated(currentAuthentication.isAuthenticated());
        return passwordLessUserNameAuthentication;
    }

    public interface UsernameCollector {
        String getUserName(X509Certificate[] certificatesChain);
    }

    public interface AuthoritiesCollector {
        Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain);
    }
}
