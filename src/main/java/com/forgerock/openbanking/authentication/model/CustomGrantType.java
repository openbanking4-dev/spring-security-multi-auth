package com.forgerock.openbanking.authentication.model;

import org.springframework.security.core.GrantedAuthority;

public enum CustomGrantType implements GrantedAuthority {
    INTERNAL;

    @Override
    public String getAuthority() {
        return name();
    }
}
