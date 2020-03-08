package org.apache.shiro.realm.jwt;

import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.ShiroException;

import java.security.Principal;
import java.text.ParseException;
import java.util.Collections;
import java.util.Set;

/**
 * Wraps a JWT token in a Principal object.
 */
public class JwtPrincipal implements Principal {

    private final SignedJWT signedJWT;

    public JwtPrincipal(SignedJWT signedJWT) {
        this.signedJWT = signedJWT;
    }

    public Set<String> getRoles() {
        try {
            Set<String> roles = JwtUtil.getRoles(signedJWT);
            if (roles == null) {
                return Collections.emptySet();
            }
            return roles;
        } catch (ParseException exception) {
            throw new ShiroException("cannot get roles from JWT");
        }
    }

    @Override
    public String getName() {
        try {
            return JwtUtil.getPrincipal(signedJWT);
        } catch (ParseException exception) {
            throw new ShiroException("cannot get principal from JWT");
        }
    }
}
