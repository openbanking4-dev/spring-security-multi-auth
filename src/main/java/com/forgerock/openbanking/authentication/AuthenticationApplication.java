package com.forgerock.openbanking.authentication;

import com.forgerock.openbanking.authentication.configurers.MultiAuthenticationCollectorConfigurer;
import com.forgerock.openbanking.authentication.configurers.PasswordLessUserNameAuthentication;
import com.forgerock.openbanking.authentication.configurers.collectors.StatelessAccessTokenCollector;
import com.forgerock.openbanking.authentication.configurers.collectors.X509Collector;
import com.forgerock.openbanking.authentication.model.CustomGrantType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
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
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
							.collector(X509Collector.builder()
									.usernameCollector(selfSignedCertificates)
									.authoritiesCollector(selfSignedCertificates)
									.build())
							.collectorForAuthorzation(StatelessAccessTokenCollector.builder()
									.build())
					)
			;
		}
	}

	public static class CustomAuthProvider implements AuthenticationProvider {
		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			//You can load more GrantedAuthority based on the user subject
			return authentication;
		}

		@Override
		public boolean supports(Class<?> aClass) {
			return true;
		}
	}

	@Slf4j
	public static class SelfSignedCertificates implements X509Collector.AuthoritiesCollector, X509Collector.UsernameCollector {

		private static final String JAVA_KEYSTORE = "JKS";

		@Value("${server.ssl.self-signed.ca-alias}")
		private String caAlias;

		@Override
		public Set<GrantedAuthority> getAuthorities(X509Certificate[] certificatesChain) {
			try {
				X509Certificate caCertificate = (X509Certificate) KeyStore.getInstance(JAVA_KEYSTORE).getCertificate(caAlias);

				if ((certificatesChain.length > 1 && caCertificate.equals(certificatesChain[1]))
						|| (certificatesChain.length == 1 && caCertificate.getSubjectX500Principal().equals(certificatesChain[0].getIssuerX500Principal()))) {

					return Stream.of(CustomGrantType.INTERNAL).collect(Collectors.toSet());
				}
			} catch (KeyStoreException e) {
				log.error("Can't get Self signed internal CA");
			}
			return Collections.EMPTY_SET;
		}

		@Override
		public String getUserName(X509Certificate[] certificatesChain) {
			return certificatesChain[0].getSubjectDN().getName();
		}
	}
}