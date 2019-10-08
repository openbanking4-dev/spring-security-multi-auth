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
package com.forgerock.openbanking.authentication.model.authentication;

import com.forgerock.cert.Psd2CertInfo;
import org.springframework.security.core.GrantedAuthority;

import java.security.cert.X509Certificate;
import java.util.Collection;

public class PSD2Authentication extends X509Authentication {

    private Psd2CertInfo psd2CertInfo;

    public PSD2Authentication(String username, Collection<? extends GrantedAuthority> authorities, X509Certificate[] chain, Psd2CertInfo psd2CertInfo) {
        super(username, authorities, chain);
        this.psd2CertInfo = psd2CertInfo;
    }

    public Psd2CertInfo getPsd2CertInfo() {
        return psd2CertInfo;
    }
}