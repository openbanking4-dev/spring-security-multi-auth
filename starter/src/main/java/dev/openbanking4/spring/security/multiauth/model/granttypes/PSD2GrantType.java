/*
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
package dev.openbanking4.spring.security.multiauth.model.granttypes;

import com.forgerock.cert.psd2.RoleOfPsp;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;

@Slf4j
@AllArgsConstructor
@Data
public class PSD2GrantType implements GrantedAuthority {

    private RoleOfPsp roleOfPsp;

    @Override
    public String getAuthority() {
        return "PSD2_" + roleOfPsp.getRole().name();
    }
}
