package org.apache.shiro.realm.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class JwtUtil {

    /**
     * Gets principal from JWT claim set
     *
     * @param jwtClaimsSet the claim set
     * @return value of upn claim, or null when not available
     * @throws ParseException on invalid token
     */
    public static String getPrincipal(JWTClaimsSet jwtClaimsSet) throws ParseException {
        if (jwtClaimsSet == null) {
            return null;
        }
        return jwtClaimsSet.getStringClaim(Claims.upn.name());
    }

    /**
     * Gets roles from JWT claim set
     *
     * @param jwtClaimsSet the claim set
     * @return value of roles claim, or null when  not available
     * @throws ParseException on invalid token
     */
    public static Set<String> getRoles(JWTClaimsSet jwtClaimsSet) throws ParseException {
        if (jwtClaimsSet == null) {
            return null;
        }
        List<String> roles = jwtClaimsSet.getStringListClaim(Claims.groups.name());
        if (roles == null) {
            return null;
        }
        return new HashSet<>(roles);
    }

    private enum Claims {
        upn, // MP-JWT specific unique principal name,
        groups // MP-JWT specific groups permission grant
    }
}
