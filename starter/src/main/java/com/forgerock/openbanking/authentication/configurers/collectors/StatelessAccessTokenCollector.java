/**
 * The contents of this file are subject to the terms of the Common Development and
 *  Distribution License (the License). You may not use this file except in compliance with the
 *  License.
 *
 *  You can obtain a copy of the License at https://forgerock.org/cddlv1-0/. See the License for the
 *  specific language governing permission and limitations under the License.
 *
 *  When distributing Covered Software, include this CDDL Header Notice in each file and include
 *  the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 *  Header, with the fields enclosed by brackets [] replaced by your own identifying
 *  information: "Portions copyright [year] [name of copyright owner]".
 *
 *  Copyright 2019 ForgeRock AS.
 */
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
