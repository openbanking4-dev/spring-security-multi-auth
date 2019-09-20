package com.forgerock.openbanking.authentication.configurers.collectors;

import com.forgerock.openbanking.authentication.model.granttypes.ScopeGrantType;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.util.stream.Collectors;

@Slf4j
@ToString
@Builder
@Getter
public class StatelessAccessTokenCollector extends AccessTokenCollector<JWT> {

    public StatelessAccessTokenCollector() {

        this.authoritiesCollector = token -> token.getJWTClaimsSet().getStringListClaim("scope")
                .stream()
                .map(s -> new ScopeGrantType(s)).collect(Collectors.toSet());
        this.tokenValidator = token -> JWTParser.parse(token);
    }
}
