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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTParser;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.CustomJwtCookieCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StatelessAccessTokenCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StaticUserCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.X509Collector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.stream.Collectors;

@RestController
@SpringBootApplication
@EnableWebSecurity

public class AuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationApplication.class, args);
	}

	@Autowired
	private ObjectMapper objectMapper;
	@GetMapping("/whoIAm")
	public String whoIAm(Principal principal) throws JsonProcessingException {
		return objectMapper.writeValueAsString(((Authentication) principal).getPrincipal());
	}

	@Configuration
	static class CookieWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http

					.authorizeRequests()
					.anyRequest()
					.permitAll()
					.and()
					.authenticationProvider(new CustomAuthProvider())
					.apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()

							/**
							 * Authentication & authorisation via a cookie 'SSO'
							 * The authorities are extracted from the 'group' claim
							 * The username is extracted from the 'sub' claim
							 * Note: JWT cookies expected to be signed with HMAC with "password" as a secret
							 */
							.collector(CustomJwtCookieCollector.builder()
									.collectorName("Cookie-SESSION")
									.authoritiesCollector(token -> token.getJWTClaimsSet().getStringListClaim("group").stream()
											.map(g -> new SimpleGrantedAuthority(g)).collect(Collectors.toSet()))
									.tokenValidator(tokenSerialised -> {
										JWSObject jwsObject = JWSObject.parse(tokenSerialised);
										JWSVerifier verifier = new MACVerifier("Qt5y2isMydGwVuREoIomK9Ei70EoFQKH0GpcbtJ4");
										jwsObject.verify(verifier);
										return JWTParser.parse(tokenSerialised);
									})
									.cookieName("SSO")
									.build())

							/**
							 * Authentication via a certificate
							 * The username is the certificate subject.
							 * We don't expect this app to do the SSL termination, therefore we will trust the header x-cert
							 * populated by the gateway
							 */
							.collectorForAuthentication(X509Collector.x509Builder()
									.collectorName("PSD2-cert")
									.usernameCollector(certificatesChain -> certificatesChain[0].getSubjectDN().getName())
									.collectFromHeader(CertificateHeaderFormat.PEM)
									.headerName("x-cert")
									.build())

							/**
							 * Authorization via an access token
							 * The authorities are extracted from the 'scope' claim
							 * Note: For simplification, the access token is signed with HMAC. In a real scenario, we would have
							 * called the JWK_URI of the AS
							 */
							.collectorForAuthorzation(StatelessAccessTokenCollector.builder()
									.collectorName("stateless-access-token")
									.tokenValidator(tokenSerialised -> {
										JWSObject jwsObject = JWSObject.parse(tokenSerialised);
										JWSVerifier verifier = new MACVerifier("Qt5y2isMydGwVuREoIomK9Ei70EoFQKH0GpcbtJ4");
										jwsObject.verify(verifier);
										return JWTParser.parse(tokenSerialised);
									})
									.build()
							)
							/**
							 * Static authentication
							 * If no authentication was possible with the previous collector, we default to the anonymous user
							 */
							.collectorForAuthentication(StaticUserCollector.builder()
									.collectorName("StaticUser-anonymous")
									.usernameCollector(() -> "anonymous")
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
}