package org.apache.shiro.jwt;

import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;

/**
 * Filter for extracting JWT token from HTTP request. This filter does not validate the token.
 * Configure a {@link JwtRealm} for validating tokens and extracting roles.
 */
@Slf4j
public class JwtFilter extends AccessControlFilter {

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // Do not create sessions
        request.setAttribute(DefaultSubjectContext.SESSION_CREATION_ENABLED, Boolean.FALSE);
        return super.onPreHandle(request, response, mappedValue);
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        AuthenticationToken token = createAuthenticationToken(request);
        try {
            Subject subject = getSubject(request, response);
            subject.login(token);
            return onAuthorizationSuccess(token, subject, request, response);
        } catch (AuthenticationException exception) {
            return onAuthenticationFailure(token, exception, request, response);
        } catch (AuthorizationException exception) {
            return onAuthorizationFailure(token, exception, request, response);
        }
    }

    protected boolean onAuthorizationSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response) {
        return true;
    }

    protected boolean onAuthenticationFailure(AuthenticationToken token, AuthenticationException exception, ServletRequest request, ServletResponse response) {
        log.warn("{}: unauthenticated request from {}", request.getServletContext(), request.getRemoteAddr());
        return false;
    }

    protected boolean onAuthorizationFailure(AuthenticationToken token, AuthorizationException exception, ServletRequest request, ServletResponse response) {
        log.warn("{}: unauthorized request from {}", request.getServletContext(), request.getRemoteAddr());
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) {
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        return false;
    }

    protected AuthenticationToken createAuthenticationToken(ServletRequest request) {
        String header = getAuthorizationHeader(request);
        SignedJWT signedJWT = JwtUtil.extractJwtToken(header);
        return new JwtAuthenticationToken(signedJWT);
    }

    private static String getAuthorizationHeader(ServletRequest request) {
        HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
        String header = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || header.length() == 0) {
            throw new UnauthorizedException("missing Authorization header");
        }
        return header;
    }
}