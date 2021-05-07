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

import com.forgerock.cert.eidas.EidasCertType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.*;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.authentication.X509Authentication;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@SpringBootApplication
@EnableWebSecurity
@Slf4j
public class AuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationApplication.class, args);
	}

	@GetMapping("/whoAmI")
	public Object whoAmI(Principal principal) {
		return ((Authentication) principal).getPrincipal();
	}

	@Configuration
	static class MultiAuthWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
				.anyRequest()
				.permitAll()
				.and()
				.apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()
					/**
					 * Authentication & authorisation via a cookie 'SSO'
					 * The authorities are extracted from the 'group' claim
					 * The username is extracted from the 'sub' claim
					 * Note: JWT cookies expected to be signed with HMAC with "Qt5y2isMydGwVuREoIomK9Ei70EoFQKH0GpcbtJ4"
					 * as a secret
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
					 * Authentication via an API key
					 * The username is extracted by calling your API key service
					 */
					.collectorForAuthentication(APIKeyCollector.<User>builder()
						.collectorName("API-Key")
						.apiKeyExtractor(req -> req.getParameter("key"))
						.apiKeyValidator(apiKey -> {
							//Here call the API key validator service.
							return new User("bob", "",
									Stream.of(new SimpleGrantedAuthority("repo-32")).collect(Collectors.toSet()));
						})
						.usernameCollector(User::getUsername)
						.build())

					/**
					 * Authentication via a certificate
					 * The username is the certificate subject.
					 * We don't expect this app to do the SSL termination, therefore we will trust the header x-cert
					 * populated by the gateway
					 */
					.collectorForAuthentication(X509Collector.x509Builder()
						.collectorName("x509-cert")
						.usernameCollector(certificatesChain -> certificatesChain[0].getSubjectDN().getName())
						.collectFromHeader(CertificateHeaderFormat.PEM)
						.headerName("x-cert")
						.build())

					/**
					 * Checks for PSD2 Certificates and if it's a QSEAL returns the principal name else returns null
					 */
					.collectorForAuthentication(PSD2Collector.psd2Builder()
						.collectorName("PSD2Collector")
							.psd2UsernameCollector((certificatesChain, psd2CertInfo) -> {
								String userName = null;
								if (psd2CertInfo.isPsd2Cert() &&
										psd2CertInfo.getEidasCertType().get() == EidasCertType.WEB) {
									if (certificatesChain[0] != null) {
										userName = certificatesChain[0].getSubjectDN().getName();
									} else {
										throw new IllegalArgumentException("certificateChain must not contain null " +
												"entries");
									}
								} else {
									log.info("PSD2 Certificate is not a QSeal - we expect a QSEAL for authentication." +
											" Eidas cert type is '{}'", psd2CertInfo.getEidasCertType().get());
								}
								return userName;
							})
							.collectFromHeader(CertificateHeaderFormat.PEM)
							.headerName("x-cert")
							.build())

					/**
					 * Authorization via an access token
					 * The authorities are extracted from the 'scope' claim
					 * Note: For simplification, the access token is signed with HMAC, using the secret
					 * 'Qt5y2isMydGwVuREoIomK9Ei70EoFQKH0GpcbtJ4'. In a real scenario, we would have called the JWK_URI
					 * of the AS
					 */
					.collectorForAuthorzation(StatelessAccessTokenCollector.builder()
						.collectorName("stateless-access-token")
						.tokenValidator((tokenSerialised, currentAuthentication) -> {
							JWSObject jwsObject = JWSObject.parse(tokenSerialised);
							JWSVerifier verifier = new MACVerifier("Qt5y2isMydGwVuREoIomK9Ei70EoFQKH0GpcbtJ4");
							jwsObject.verify(verifier);
							JWT jwt = JWTParser.parse(tokenSerialised);
							JSONObject cnf = jwt.getJWTClaimsSet().getJSONObjectClaim("cnf");
							if (cnf != null) {
								// We need to verify the token binding
								String certificateThumbprint = cnf.getAsString("x5t#S256");
								if (certificateThumbprint == null) {
									throw new BadCredentialsException("Claim 'x5t#S256' is not defined but cnf " +
											"present. Access token format is invalid.");
								}
								if (!(currentAuthentication instanceof X509Authentication)) {
									throw new BadCredentialsException("Request not authenticated with a client cert");
								}
								X509Authentication x509Authentication = (X509Authentication) currentAuthentication;
								String clientCertThumbprint;
								try {
									clientCertThumbprint = getThumbprint(x509Authentication.getCertificateChain()[0]);
								} catch (NoSuchAlgorithmException | CertificateEncodingException e) {
									throw new RuntimeException("Can't compute thumbprint of client certificate", e);
								}
								if (!certificateThumbprint.equals(clientCertThumbprint)) {
									throw new BadCredentialsException("The thumbprint from the client certificate '"
											+ clientCertThumbprint + "' doesn't match the one specify in the access " +
											"token '" + certificateThumbprint + "'");
								}
							}

							return jwt;
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

	private static String getThumbprint(X509Certificate cert)
			throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		String digestHex = DatatypeConverter.printHexBinary(digest);
		return digestHex.toLowerCase();
	}
}