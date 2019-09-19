package com.forgerock.openbanking.authentication.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.Map;

@Service
public class JwtDecoders {
    @Autowired
    private RestTemplate restTemplate;

    public JwtDecoder fromOidcIssuerLocation(String oidcIssuerLocation) throws IOException, ParseException {
        Map<String, Object> openidConfiguration = getOpenidConfiguration(oidcIssuerLocation);
        OAuth2JwtDecoder jwtDecoder = new OAuth2JwtDecoder(openidConfiguration.get("jwks_uri").toString());
        return jwtDecoder;
    }

    private Map<String, Object> getOpenidConfiguration(String issuer) {
        ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<Map<String, Object>>() {
        };

        try {
            URI uri = UriComponentsBuilder.fromUriString(issuer + "/.well-known/openid-configuration").build().toUri();
            RequestEntity<Void> request = RequestEntity.get(uri).build();
            return (Map)restTemplate.exchange(request, typeReference).getBody();
        } catch (RuntimeException var5) {
            throw new IllegalArgumentException("Unable to resolve the OpenID Configuration with the provided Issuer of \"" + issuer + "\"", var5);
        }
    }

    private JwtDecoders() {
    }
}
