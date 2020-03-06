package org.apache.shiro.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class JwtParser {

    private static final String BEARER = "Bearer";

    /**
     * Extracts JWT bearer token from HTTP Authorization header
     * @param authorizationHeader value of the Authorization header
     * @return parsed JWT token
     * @throws ParseException invalid header or token
     */
    public static SignedJWT extractJwtToken(String authorizationHeader) throws ParseException {
        String[] parts = authorizationHeader.split("\\s+");
        if (parts.length != 2 || !parts[0].equalsIgnoreCase(BEARER)) {
            throw new ParseException("missing Bearer token", 0);
        }
        return SignedJWT.parse(parts[1]);
    }

    /**
     * Gets principal from JWT token
     *
     * @param signedJWT the JWT token
     * @return value of upn claim, or null when not available
     * @throws ParseException on invalid token
     */
    public static String getPrincipal(SignedJWT signedJWT) throws ParseException {
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        if (jwtClaimsSet == null) {
            return null;
        }
        return jwtClaimsSet.getStringClaim(Claims.upn.name());
    }

    /**
     * Gets roles from JWT token
     *
     * @param signedJWT the JWT token
     * @return value of roles claim, or null when  not available
     * @throws ParseException on invalid token
     */
    public static Set<String> getRoles(SignedJWT signedJWT) throws ParseException {
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
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
