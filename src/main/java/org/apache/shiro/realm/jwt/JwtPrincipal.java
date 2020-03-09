package org.apache.shiro.realm.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authz.Permission;

import java.security.Principal;
import java.text.ParseException;
import java.util.Collections;
import java.util.Set;

/**
 * Wraps a JWT token in a Principal object.
 */
public class JwtPrincipal implements Principal {

    private final JWTClaimsSet jwtClaimsSet;
    private Set<Permission> permissions;

    public JwtPrincipal(JWTClaimsSet jwtClaimsSet) {
        this.jwtClaimsSet = jwtClaimsSet;
    }

    public Set<String> getRoles() {
        try {
            Set<String> roles = JwtUtil.getRoles(jwtClaimsSet);
            if (roles == null) {
                return Collections.emptySet();
            }
            return roles;
        } catch (ParseException exception) {
            throw new ShiroException("cannot get roles from JWT");
        }
    }

    public Set<Permission> getPermissions() {
        return permissions == null ? Collections.emptySet() : permissions;
    }

    protected void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    @Override
    public String getName() {
        try {
            return JwtUtil.getPrincipal(jwtClaimsSet);
        } catch (ParseException exception) {
            throw new ShiroException("cannot get principal from JWT");
        }
    }
}
