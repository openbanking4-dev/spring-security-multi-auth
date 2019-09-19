package com.forgerock.openbanking.authentication.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.*;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;


public class OAuth2JwtDecoder  implements JwtDecoder {
    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";
    private final JWSAlgorithm jwsAlgorithm;
    private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter;
    private OAuth2TokenValidator<Jwt> jwtValidator;
    private JWKSet jwkSet;

    public OAuth2JwtDecoder(String jwkSetUrl) throws IOException, ParseException {
        this(jwkSetUrl, "EC256");
    }

    public OAuth2JwtDecoder(String jwkSetUrl, String jwsAlgorithm) throws IOException, ParseException {
        this.claimSetConverter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
        this.jwtValidator = JwtValidators.createDefault();
        Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");
        Assert.hasText(jwsAlgorithm, "jwsAlgorithm cannot be empty");
        this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm);
    }

    public Jwt decode(String token) throws JwtException {
        JWT jwt = this.parse(token);
        if (jwt instanceof SignedJWT) {
            Jwt createdJwt = this.createJwt(token, jwt);
            return this.validateJwt(createdJwt);
        } else {
            throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
        }
    }

    private JWT parse(String token) {
        try {
            return JWTParser.parse(token);
        } catch (Exception var3) {
            throw new JwtException(String.format("An error occurred while attempting to decode the Jwt: %s", var3.getMessage()), var3);
        }
    }

    private Jwt createJwt(String token, JWT parsedJwt) {
        try {
            JWTClaimsSet jwtClaimsSet = parsedJwt.getJWTClaimsSet();
            Map<String, Object> headers = new LinkedHashMap(parsedJwt.getHeader().toJSONObject());
            Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());
            Instant expiresAt = (Instant)claims.get("exp");
            Instant issuedAt = (Instant)claims.get("iat");
            Jwt jwt = new Jwt(token, issuedAt, expiresAt, headers, claims);
            return jwt;
        } catch (Exception var10) {
            if (var10.getCause() instanceof ParseException) {
                throw new JwtException(String.format("An error occurred while attempting to decode the Jwt: %s", "Malformed payload"));
            } else {
                throw new JwtException(String.format("An error occurred while attempting to decode the Jwt: %s", var10.getMessage()), var10);
            }
        }
    }

    private Jwt validateJwt(Jwt jwt) {
        OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
        if (result.hasErrors()) {
            String description = (result.getErrors().iterator().next()).getDescription();
            throw new JwtValidationException(String.format("An error occurred while attempting to decode the Jwt: %s", description), result.getErrors());
        } else {
            return jwt;
        }
    }
}
