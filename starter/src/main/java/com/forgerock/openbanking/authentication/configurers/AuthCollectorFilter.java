package com.forgerock.openbanking.authentication.configurers;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Slf4j
@AllArgsConstructor
public class AuthCollectorFilter extends GenericFilterBean {

    private List<AuthCollector> authentificationCollectors;
    private List<AuthCollector> authorizationCollectors;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;
        for (AuthCollector authCollector : authentificationCollectors) {
            Authentication authentication = authCollector.collectAuthentication((HttpServletRequest) req);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
                break;
            }
        }

        Authentication currentAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (currentAuthentication == null) {
            currentAuthentication = new PasswordLessUserNameAuthentication("", Collections.EMPTY_SET);
        } else {
            currentAuthentication.setAuthenticated(true);
        }

        for (AuthCollector authCollector : authorizationCollectors) {
            currentAuthentication = authCollector.collectAuthorisation((HttpServletRequest) req, currentAuthentication);
        }
        if (currentAuthentication != null) {
            SecurityContextHolder.getContext().setAuthentication(currentAuthentication);
        }
        chain.doFilter(request, response);
    }

}
