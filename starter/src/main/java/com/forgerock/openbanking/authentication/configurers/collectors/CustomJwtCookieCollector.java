package com.forgerock.openbanking.authentication.configurers.collectors;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

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
