package com.forgerock.openbanking.authentication.model.granttypes;

import org.springframework.security.core.GrantedAuthority;

public enum CustomGrantType implements GrantedAuthority {
    INTERNAL;

    @Override
    public String getAuthority() {
        return "CUSTOM_" + name();
    }
}
