package com.forgerock.openbanking.authentication.configurers.collectors;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;

@Slf4j
@ToString
@Builder
@Getter
@AllArgsConstructor
public class CustomJwtCookieCollector extends CustomCookieCollector<JWT> {

    private String issuerJwkUri;
    private String issuerId;

    private JWKSet jwkSet;

    public CustomJwtCookieCollector() throws IOException, ParseException {
        jwkSet = JWKSet.load(new URL(issuerJwkUri));
        this.tokenValidator = tokenSerialised -> JWTParser.parse(tokenSerialised);
        this.usernameCollector = token -> token.getJWTClaimsSet().getSubject();
    }
}
