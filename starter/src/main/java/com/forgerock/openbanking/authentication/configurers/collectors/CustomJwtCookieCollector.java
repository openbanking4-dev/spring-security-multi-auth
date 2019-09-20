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
@Getter
public class CustomJwtCookieCollector extends CustomCookieCollector<JWT> {

    @Builder
    public CustomJwtCookieCollector(AuthoritiesCollector<JWT> authoritiesCollector, String cookieName) {
        super(
                tokenSerialised -> JWTParser.parse(tokenSerialised),
                token -> token.getJWTClaimsSet().getSubject(),
                authoritiesCollector,
                cookieName
        );
    }
}
