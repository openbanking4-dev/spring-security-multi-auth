| |Current Status|
|---|---|
|Build|[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fopenbanking4-dev%2Fspring-security-multi-auth%2Fbadge%3Fref%3Dmaster&style=flat)](https://actions-badge.atrox.dev/openbanking4-dev/spring-security-multi-auth/goto?ref=master)|
|Code coverage|[![codecov](https://codecov.io/gh/openbanking4-dev/spring-security-multi-auth/branch/master/graph/badge.svg)](https://codecov.io/gh/openbanking4-dev/spring-security-multi-auth)
|Bintray|[![Bintray](https://img.shields.io/bintray/v/openbanking4-dev/openbanking4-dev/spring-security-multi-auth.svg?maxAge=2592000)](https://bintray.com/openbanking4-dev/openbanking4-dev/spring-security-multi-auth)|
|License|![license](https://img.shields.io/github/license/ACRA/acra.svg)|

Spring security multi-auth 
========================

Extend Spring security to provide a multi-auth configurer. Create custom authentication method, add more than one 
authentication methods to an endpoint. You can also authenticate using one method and authorize using another.
A typical way would be to use certificate authentication (MATLS) but collect authorisation using an access token.
 

# Motivation of this project

## Easy way to create custom authentication configurers

Spring security offers authentication configurers out of the box, like X509, rememberMe, etc.
Defining a new authentication collector in Spring security is possible but requires a configurer and a filter.
The first objective of this project is to offer you an easier way to implement authentication configurer.

Instead of creating an authentication configurer directly, which requires defining a configurer and a filter, you define
authentication and authorization collectors. Much friendly to implement, you concentrate on the auth and the integration
with the spring framework is handle for you by this library.

## Multiple authentications in parallel

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

```xml
<dependency>
    <groupId>dev.openbanking4.spring.security</groupId>
    <artifactId>spring-security-multi-auth-starter</artifactId>
    <version>{project.version}</version>
</dependency>
```

```xml
<repositories>
  <repository>
    <id>jcenter</id>
    <url>https://jcenter.bintray.com/</url>
  </repository>
</repositories>
```

## examples:

We created a dedicated repo [https://github.com/openbanking4-dev/spring-security-multi-auth-examples](https://github.com/openbanking4-dev/spring-security-multi-auth-examples) to provide examples of how you can use the library.

