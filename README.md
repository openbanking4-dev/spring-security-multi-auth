[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fopenbanking4-dev%2Fspring-security-multi-auth%2Fbadge%3Fref%3Dmaster&style=flat)](https://actions-badge.atrox.dev/openbanking4-dev/spring-security-multi-auth/goto?ref=master)
![GitHub](https://img.shields.io/github/license/openbanking4-dev/spring-security-multi-auth)
[![codecov](https://codecov.io/gh/openbanking4-dev/spring-security-multi-auth/branch/master/graph/badge.svg)](https://codecov.io/gh/openbanking4-dev/spring-security-multi-auth)

Spring security multi-auth 
========================

# Motivation of this project

## Easy way to create custom authentication configurers

Spring security offers authentication configurers out of the box, like X509, rememberMe, etc.
Defining a new authentication collector in Spring security is possible but requires a configurer and a filter.
The first objective of this project is to offer you an easier way to implement authentication configurer.

Instead of creating an authentication configurer directly, which requires defining a configurer and a filter, you define
authentication and authorization collectors. Much friendly to implement, you concentrate on the auth and the integration
with the spring framework is handle for you by this library.

## Multiple authentication in parallel

After the lack of easy customisation of authentication collector, the second issue we met was the lack of multiple authentication method in Spring.
Most of the time, your application will be protecting all their APIs using the same auth method (cookie, certificate, headers, etc) and Spring
is working well for that.
Although if you start to offer APIs, consumable with different auth method, like an API key or a certificate, or a cookie and an access token,
Spring is not going to be that flexible.

This project offers a way to add multiple authentication collector, which would be evaluated in the order of declaration.
This way, you can define certificate auth and Cookie Auth for the same endpoints.

## Separating authentication to authorization

Another issue we met in Spring, is the lack of distinction between authentication and authorisation. This becomes blatant when we talk about access token.
Access token are really about access and not authentication. You would expect to use a different authentication method associated with an access token.
A usual way is to offer MATLS with access token based. With token biding, you can actually verify that the client certificate matches the access token.

In this library, you will see that we separate the notion of authentication and authorization. A collector can do both, like
a cookie can identify the user 'toto' and know his different group that defines what he can and can't do.
Some can concentrate on one aspect, like the access token collector would only offer authorization.

We end up with three kind of collectors:

* Authentication collector: they only do authentication, meaning they identify the user but won't be in charge of knowing what they can or can't do. Certificates authentication (x509Collector) is a good example of it.
* Authorization collector: they only do authorization, meaning they won't be able to tell you who is consuming the service, but they can tell you what they are authorized to do. An access token is a good example of this scenario.
* Both authentication and authorization: some collectors are good to do both, like a cookie. This fall back to what you are more used to use in Spring.


# Features

* Easier way to add authentication collector
* separating authentication to authorisation
* Add multiple authentication and authorisation available.
* out of the box auth collector:
    * Access token
    * Stateless access token
    * Stateful access token
    * API key
    * Custom cookie
    * Custom cookie as JWT
    * X509 collector
    * PSD2 collector
    
    
 #  How to use?
 
We based on spring security. Like you are used to do, you define a `WebSecurityConfigurerAdapter`. The only difference is with this library, we extended spring
to offer a `MultiAuthenticationCollectorConfigurer`.

## How to install

Add the following dependency:

```$xslt
<dependency>
    <groupId>dev.openbanking4.spring.security</groupId>
    <artifactId>spring-security-multi-auth-starter</artifactId>
    <version>${project.version}</version>
</dependency>
```

## examples

Here is different example of how you can use the `MultiAuthenticationCollectorConfigurer`:

### Certificate + Access token

One of the use-case that motivated us to defined this library. Basically, your endpoints are protected by MATLS and your
resources by OAuth 2.0. It's the scenario choose by Open Banking UK by the way.


```$xslt
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
					)
			;
		}
	}
```

### Cookie + API key

One of the use-case that motivated us to defined this library. Basically, your endpoints are protected by MATLS and your
resources by OAuth 2.0. It's the scenario choose by Open Banking UK by the way.


```$xslt
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

							)
					)
			;
		}
	}
```