package com.forgerock.openbanking.authentication;

import com.forgerock.openbanking.authentication.service.JwtDecoders;
import com.forgerock.openbanking.authentication.service.MATLSAuthentication;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.IssuerUriCondition;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.web.server.Ssl;
import org.springframework.context.annotation.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.apache.http.ssl.SSLContextBuilder;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URL;
import java.security.Principal;
import java.text.ParseException;

@RestController
@SpringBootApplication
@EnableWebSecurity

public class AuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationApplication.class, args);
	}

	@GetMapping("/cookie/hello")
	//@PreAuthorize("hasAuthority('SCOPE_accounts')")
	public String sayHelloWithCookieAuth(Principal principal) {
		return "Hello, " + principal;
	}

	@GetMapping("/resource-server/hello")
	@PreAuthorize("hasAuthority('SCOPE_accounts')")
	public String sayHelloWithResourceServer(Principal principal) {
		return "Hello, " + principal;
	}

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class OAuth2WebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http

					.authorizeRequests()
					.antMatchers("/cookie/**")
					.authenticated()
					.and()
					.x509().subjectPrincipalRegex("/(.*)")
					.userDetailsService(new MATLSAuthentication())
					.and()
					.authenticationProvider(new CustomAuthenticationProvider())
			;

			http.authorizeRequests()
					.antMatchers("/resource-server/**")
					.authenticated()
					.and()
					.x509().subjectPrincipalRegex("(.*)")
					.userDetailsService(new MATLSAuthentication())
					.and()
					.oauth2ResourceServer().jwt();


		}
	}

	@Bean
	@Conditional({IssuerUriCondition.class})
	@ConditionalOnMissingBean
	public JwtDecoder jwtDecoderByIssuerUri(OAuth2ResourceServerProperties properties, JwtDecoders jwtDecoders) throws IOException, ParseException {
		return jwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
	}

	//Because it's untrusted certificate from the AS
	@Bean
	@Primary
	public RestTemplate restTemplate(@Value("${trust-store.path}") String trustStoreUrl,
							  @Value("${trust-store.password}") String trustStorePassword) throws Exception {
		SSLContext sslContext = new SSLContextBuilder()
				.loadTrustMaterial(ResourceUtils.getURL(trustStoreUrl), trustStorePassword.toCharArray())
				.build();
		SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
		HttpClient httpClient = HttpClients.custom()
				.setSSLSocketFactory(socketFactory)
				.build();
		HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
		return new RestTemplate(factory);
	}
}