package com.forgerock.openbanking.authentication.model.granttypes;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;

@Slf4j
@AllArgsConstructor
@Data
public class ScopeGrantType implements GrantedAuthority {
    private String scopeName;

    @Override
    public String getAuthority() {
        return "SCOPE_" + scopeName;
    }
}
