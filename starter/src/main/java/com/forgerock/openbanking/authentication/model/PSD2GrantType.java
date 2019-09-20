package com.forgerock.openbanking.authentication.model;

import com.forgerock.cert.psd2.RoleOfPsp;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;

@Slf4j
@AllArgsConstructor
@Data
public class PSD2GrantType implements GrantedAuthority {

    private RoleOfPsp roleOfPsp;

    @Override
    public String getAuthority() {
        return "PSD2_" + roleOfPsp.getRole().name();
    }
}
