package com.forgerock.openbanking.authentication.configurers;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

public interface AuthCollector {

    Authentication collectAuthentication(HttpServletRequest request);

    Authentication collectAuthorisation(HttpServletRequest req, Authentication currentAuthentication);
}
