package com.forgerock.openbanking.authentication.configurers.collectors;

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.eidas.EidasCertType;
import com.forgerock.cert.exception.InvalidEidasCertType;
import com.forgerock.cert.exception.InvalidPsd2EidasCertificate;
import com.forgerock.cert.psd2.Psd2QcStatement;
import com.forgerock.cert.psd2.RolesOfPsp;
import com.forgerock.openbanking.authentication.configurers.AuthCollector;
import com.forgerock.openbanking.authentication.configurers.PasswordLessUserNameAuthentication;
import com.forgerock.openbanking.authentication.model.CustomGrantType;
import com.forgerock.openbanking.authentication.model.PSD2GrantType;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class PSD2Collector extends X509Collector {
    private UsernameCollector usernameCollector;
    private AuthoritiesCollector authoritiesCollector;

    @Builder
    public PSD2Collector(UsernameCollector usernameCollector, AuthoritiesCollector authoritiesCollector) {
        super(usernameCollector, certificatesChain -> {
            Set<GrantedAuthority> authorities = new HashSet<>();
            try {
                Psd2CertInfo psd2CertInfo = new Psd2CertInfo(certificatesChain);
                if (psd2CertInfo.getEidasCertType().isPresent() && psd2CertInfo.getEidasCertType().equals(EidasCertType.WEB)) {

                    //Map PSD2 roles
                    Optional<Psd2QcStatement> psd2QcStatementOpt = psd2CertInfo.getPsd2QCStatement();
                    if (psd2QcStatementOpt.isPresent()) {
                        Psd2QcStatement psd2QcStatement = psd2QcStatementOpt.get();
                        authorities.addAll(authoritiesCollector.getAuthorities(certificatesChain, psd2CertInfo, psd2QcStatement.getRoles()));
                    } else {
                        authorities.addAll(authoritiesCollector.getAuthorities(certificatesChain, psd2CertInfo, null));
                    }
                }
            } catch (InvalidPsd2EidasCertificate | InvalidEidasCertType invalidPsd2EidasCertificate) {
                invalidPsd2EidasCertificate.printStackTrace();
            }

            authorities.addAll(authoritiesCollector.getAuthorities(certificatesChain, null, null));
            return authorities;
        });

    }

    public interface AuthoritiesCollector {
        Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles);
    }
}
