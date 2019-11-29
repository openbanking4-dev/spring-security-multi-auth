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
package dev.openbanking4.spring.security.multiauth;

import com.forgerock.cert.Psd2CertInfo;
import com.forgerock.cert.psd2.RolesOfPsp;
import com.nimbusds.jwt.JWTParser;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.CustomJwtCookieCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.PSD2Collector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StatelessAccessTokenCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.X509Collector;
import dev.openbanking4.spring.security.multiauth.model.granttypes.CustomGrantType;
import dev.openbanking4.spring.security.multiauth.model.granttypes.PSD2GrantType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@SpringBootApplication
@EnableWebSecurity

public class AuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationApplication.class, args);
	}

	@GetMapping("/hello")
	public String sayHello(Principal principal) {
		return "Hello, " + principal;
	}

	@Configuration
	static class CookieWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			SelfSignedCertificates selfSignedCertificates = new SelfSignedCertificates();
			http

					.authorizeRequests()
					.anyRequest()
					.permitAll()
					.and()
					.authenticationProvider(new CustomAuthProvider())
					.apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()
							.collector(CustomJwtCookieCollector.builder()
									.collectorName("Cookie-SESSION")
									.cookieName("SESSION")
									.build())
							.collector(PSD2Collector.psd2Builder()
									.collectorName("PSD2-cert")
									.usernameCollector(selfSignedCertificates)
									.authoritiesCollector(selfSignedCertificates)
									.build())
							.collectorForAuthorzation(StatelessAccessTokenCollector.builder()
									.collectorName("stateless-access-token")
									.tokenValidator(token -> JWTParser.parse(token))
									.build())
					)
			;
		}
	}

	public static class CustomAuthProvider implements AuthenticationProvider {
		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			//You can load more GrantedAuthority based on the user subject, like loading the TPP details from the software ID
			return authentication;
		}

		@Override
		public boolean supports(Class<?> aClass) {
			return true;
		}
	}

	@Slf4j
	public static class SelfSignedCertificates implements PSD2Collector.AuthoritiesCollector, X509Collector.UsernameCollector {

		private static final String JAVA_KEYSTORE = "JKS";

		@Value("${server.ssl.self-signed.ca-alias}")
		private String caAlias;

		@Override
		public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain, Psd2CertInfo psd2CertInfo, RolesOfPsp roles) {
			Set<GrantedAuthority> authorities = new HashSet<>();

			if (roles != null) {
				authorities.addAll(roles.getRolesOfPsp().stream().map(r -> new PSD2GrantType(r)).collect(Collectors.toSet()));
			}

			try {
				X509Certificate caCertificate = (X509Certificate) KeyStore.getInstance(JAVA_KEYSTORE).getCertificate(caAlias);

				if ((certificatesChain.length > 1 && caCertificate.equals(certificatesChain[1]))
						|| (certificatesChain.length == 1 && caCertificate.getSubjectX500Principal().equals(certificatesChain[0].getIssuerX500Principal()))) {

					authorities.add(CustomGrantType.INTERNAL);
				}
			} catch (KeyStoreException e) {
				log.error("Can't get Self signed internal CA");
			}

			return authorities;
		}

		@Override
		public String getUserName(X509Certificate[] certificatesChain) {
			return certificatesChain[0].getSubjectDN().getName();
		}
	}
}