package org.apache.shiro.realm.jwt;

import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authc.AuthenticationToken;

public class JwtAuthenticationToken implements AuthenticationToken {

    private final JwtPrincipal principal;
    private final SignedJWT credentials;

    public JwtAuthenticationToken(SignedJWT signedJWT) {
        principal = new JwtPrincipal(signedJWT);
        credentials = signedJWT;
    }

    @Override
    public JwtPrincipal getPrincipal() {
        return principal;
    }

    @Override
    public SignedJWT getCredentials() {
        return credentials;
    }
}
