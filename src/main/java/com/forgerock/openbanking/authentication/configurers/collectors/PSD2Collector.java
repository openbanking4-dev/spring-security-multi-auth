package com.forgerock.openbanking.authentication.configurers.collectors;

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.openbanking.authentication.configurers.AuthCollector;
import com.forgerock.openbanking.authentication.configurers.PasswordLessUserNameAuthentication;
import com.forgerock.openbanking.authentication.utils.RequestUtils;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.Set;

@Slf4j
@ToString
@Builder
@Data
@AllArgsConstructor
public class PSD2Collector implements AuthCollector {

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
        if (certificatesChain == null) {
            log.debug("No certificate received");
            return null;
        }
        try {
            Psd2CertInfo psd2CertInfo = new Psd2CertInfo(certificatesChain);
            String username = usernameCollector.getUserName(psd2CertInfo, certificatesChain);
            Set<GrantedAuthority> authorities = authoritiesCollector.getAuthorities(psd2CertInfo, certificatesChain);

            return new PasswordLessUserNameAuthentication(username, authorities);
        } catch (InvalidPsd2EidasCertificate invalidPsd2EidasCertificate) {
            invalidPsd2EidasCertificate.printStackTrace();
        }
        return null;
    }

    @Override
    public Authentication collectAuthorisation(HttpServletRequest req, Authentication currentAuthentication) {
        return null;
    }

    public interface UsernameCollector {
        String getUserName(Psd2CertInfo psd2CertInfo, X509Certificate[] certificatesChain);
    }

    public interface AuthoritiesCollector {
        Set<GrantedAuthority> getAuthorities(Psd2CertInfo psd2CertInfo, X509Certificate[] certificatesChain);
    }
}
