Spring security multi-auth 
========================



# Motivation of this project

Spring security offers authentication configurer by default, like X509, rememberMe, etc.
Their goal is to collect the user credential from the request. This is why in this project, we renamed them
'Authentication Collector', as they collect authentication information.
Defining a new authentication collector in Spring security is possible but requires a configurer and a filter.
The first objective of this project is to offer you an easier way to implement authentication collector.

After the lack of easy customisation of authentication collector, the second issue we met was the lack of multiple authentication method.
It's quite common for a micro-services to offers endpoints consumable from different services, some can authenticate using certificates (MATLS),
some using cookie and some using token bearer.
In our case, we wanted to offer APIs accessible from micro-services but also SPA.
This project offers a way to add multiple authentication collector, which would be evaluated in the order of declaration.
This way, you can define MATLS auth and Cookie Auth for the same endpoints.

Another issue we met, is the lack of distinction between authentication and authorisation. This becomes blatant when we talk about access token.
Access token are really about access and not authentication. You would expect to use a different authentication method associated with an access token.
One of the usual way is to offer MATLS with access token based. With token biding, you can actually verify that the client certificate matches the access token.
This is why we decided to separate the concept of authentication, by introducing authorisation collector.

As we did separate the authorisation from the authentication, we did also add the possibility to have multiple authorisation collectors.

# Features

* Easier way to add authentication collector
* separating authentication to authorisation
* Add multiple authentication and authorisation available.
* out of the box auth collector:
    * Access token
    * Stateless access token
    * Custom cookie
    * Custom cookie as JWT
    * PSD2 collector
    * X509 collector
    
    
 #  How to use?
 
 We did include samples spring boot apps, that will show you an example of usage of the APIs.