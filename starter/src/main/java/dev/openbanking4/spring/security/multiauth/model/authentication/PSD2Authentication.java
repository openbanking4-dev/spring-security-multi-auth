/**
 * Copyright 2019 Quentin Castel.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package dev.openbanking4.spring.security.multiauth.model.authentication;

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
