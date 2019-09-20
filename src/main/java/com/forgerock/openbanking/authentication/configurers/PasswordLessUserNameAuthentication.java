package com.forgerock.openbanking.authentication.configurers;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class PasswordLessUserNameAuthentication extends AbstractAuthenticationToken {

    private Object username;

    public PasswordLessUserNameAuthentication(Object username, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.username = username;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }
}
