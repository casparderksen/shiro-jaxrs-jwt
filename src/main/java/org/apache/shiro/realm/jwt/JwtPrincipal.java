package org.apache.shiro.realm.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authz.Permission;

import java.security.Principal;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
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
        return JwtUtil.getRoles(jwtClaimsSet);
    }

    public Set<Permission> getPermissions() {
        return permissions == null ? Collections.emptySet() : permissions;
    }

    protected void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    @Override
    public String getName() {
        Optional<String> principal = JwtUtil.getPrincipal(jwtClaimsSet);
        if (principal.isPresent()) {
            return principal.get();
        }
        throw new ShiroException("cannot get principal from JWT token");
    }
}
