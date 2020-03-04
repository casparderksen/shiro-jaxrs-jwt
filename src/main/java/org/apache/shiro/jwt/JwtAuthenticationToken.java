package org.apache.shiro.jwt;

import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.apache.shiro.authc.AuthenticationToken;

@RequiredArgsConstructor
public class JwtAuthenticationToken implements AuthenticationToken {

    private final SignedJWT signedJWT;

    @Override
    public Object getPrincipal() {
        return signedJWT;
    }

    @Override
    public Object getCredentials() {
        return signedJWT;
    }
}
