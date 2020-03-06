package org.apache.shiro.realm.jwt;

import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authc.AuthenticationToken;

public class JwtAuthenticationToken implements AuthenticationToken {

    private final String principal;
    private final SignedJWT credentials;

    public JwtAuthenticationToken(String principal, SignedJWT signedJWT) {
        this.principal = principal;
        this.credentials = signedJWT;
    }

    @Override
    public String getPrincipal() {
        return principal;
    }

    @Override
    public SignedJWT getCredentials() {
        return credentials;
    }
}
