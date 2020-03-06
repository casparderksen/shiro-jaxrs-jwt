package org.apache.shiro.jwt;

import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import java.text.ParseException;

/**
 * Filter for extracting JWT token from HTTP request. This filter does not validate the token.
 * Configure a {@link JwtRealm} for validating tokens and extracting roles.
 */
@Slf4j
public class JwtFilter extends AccessControlFilter {

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        disableSessionCreation(request);
        return super.onPreHandle(request, response, mappedValue);
    }

    private static void disableSessionCreation(ServletRequest request) {
        request.setAttribute(DefaultSubjectContext.SESSION_CREATION_ENABLED, Boolean.FALSE);
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        AuthenticationToken token = createAuthenticationToken(request);
        try {
            Subject subject = getSubject(request, response);
            subject.login(token);
            return onAuthorizationSuccess(token, subject, request, response);
        } catch (AuthenticationException | AuthorizationException exception) {
            return onAuthorizationFailure(token, exception, request, response);
        }
    }

    protected boolean onAuthorizationSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("authorized principal {}", token.getPrincipal());
        }
        return true;
    }

    protected boolean onAuthorizationFailure(AuthenticationToken token, ShiroException exception, ServletRequest request, ServletResponse response) {
        log.warn("unauthorized request for principal {} from {}", token.getPrincipal(), request.getRemoteAddr());
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) {
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        return false;
    }

    protected AuthenticationToken createAuthenticationToken(ServletRequest request) {
        try {
            String header = getAuthorizationHeader(request);
            SignedJWT signedJWT = JwtParser.extractJwtToken(header);
            return new JwtAuthenticationToken(JwtParser.getPrincipal(signedJWT), signedJWT);
        } catch (ParseException exception) {
            throw new AuthorizationException("invalid JWT token");
        }
    }

    private static String getAuthorizationHeader(ServletRequest request) {
        HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
        String header = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || header.length() == 0) {
            throw new AuthorizationException("missing Authorization header");
        }
        return header;
    }
}