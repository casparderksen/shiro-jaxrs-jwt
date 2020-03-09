package org.apache.shiro.realm.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationToken;

import java.text.ParseException;

public class JwtAuthenticationToken implements AuthenticationToken {

    private final JwtPrincipal principal;
    private final SignedJWT credentials;

    public JwtAuthenticationToken(SignedJWT signedJWT) {
        try {
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            principal = new JwtPrincipal(jwtClaimsSet);
            credentials = signedJWT;
        } catch (ParseException exception) {
            throw new ShiroException("invalid JWT token");
        }
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
