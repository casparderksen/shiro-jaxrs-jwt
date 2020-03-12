package org.apache.shiro.realm.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.shiro.ShiroException;

import java.text.ParseException;
import java.util.*;

public class JwtUtil {

    /**
     * Gets principal from JWT claim set
     *
     * @param jwtClaimsSet the claim set
     * @return optional value of upn claim
     */
    public static Optional<String> getPrincipal(JWTClaimsSet jwtClaimsSet) {
        try {
            return Optional.ofNullable(jwtClaimsSet.getStringClaim(Claims.upn.name()));
        } catch (ParseException exception) {
            throw new ShiroException(exception);
        }
    }

    /**
     * Gets roles from JWT claim set
     *
     * @param jwtClaimsSet the claim set
     * @return value of roles claim, or empty set when not available
     */
    public static Set<String> getRoles(JWTClaimsSet jwtClaimsSet) {
        try {
            List<String> roles = jwtClaimsSet.getStringListClaim(Claims.groups.name());
            return roles == null ? Collections.emptySet() : new HashSet<>(roles);
        } catch (ParseException exception) {
            throw new ShiroException(exception);
        }
    }

    private enum Claims {
        upn, // MP-JWT specific unique principal name,
        groups // MP-JWT specific groups permission grant
    }
}
