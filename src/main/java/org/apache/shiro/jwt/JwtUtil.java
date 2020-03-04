package org.apache.shiro.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.shiro.authz.AuthorizationException;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JwtUtil {

    private static final String BEARER = "Bearer";

    public static SignedJWT extractJwtToken(String authorizationHeader) {
        String[] parts = authorizationHeader.split("\\s+");
        if (parts.length != 2 || !parts[0].equalsIgnoreCase(BEARER)) {
            throw new AuthorizationException("missing Bearer token");
        }
        try {
            return SignedJWT.parse(parts[1]);
        } catch (ParseException exception) {
            throw new AuthorizationException("invalid Bearer token");
        }
    }

    public static JWTClaimsSet getJwtClaimsSet(SignedJWT signedJWT) {
        try {
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            if (jwtClaimsSet == null) {
                throw new AuthorizationException("missing claims in JWT token");
            }
            return jwtClaimsSet;
        } catch (ParseException exception) {
            throw new AuthorizationException("invalid JWT token");
        }
    }

    public static String getPrincipal(JWTClaimsSet jwtClaimsSet) {
        return getStringClaim(jwtClaimsSet, Claims.upn.name());
    }

    private static String getStringClaim(JWTClaimsSet jwtClaimsSet, String claim) {
        try {
            String principal = jwtClaimsSet.getStringClaim(claim);
            if (principal == null || principal.length() == 0) {
                throw new AuthorizationException("missing claim: " + claim);
            }
            return principal;
        } catch (ParseException e) {
            throw new AuthorizationException("invalid JWT token");
        }
    }

    public static Set<String> getRoles(JWTClaimsSet jwtClaimsSet) {
        List<String> roles = getStringListClaim(jwtClaimsSet, Claims.groups.name());
        return new HashSet<>(roles);
    }

    private static List<String> getStringListClaim(JWTClaimsSet jwtClaimsSet, String claim) {
        try {
            List<String> roles = jwtClaimsSet.getStringListClaim(claim);
            if (roles == null) {
                throw new AuthorizationException("missing claim: " + claim);
            }
            return roles;
        } catch (ParseException e) {
            throw new AuthorizationException("invalid claim: " + claim);
        }
    }


    public static boolean verifyJwtToken(SignedJWT signedJWT, RSAPublicKey rsaPublicKey) {
        try {
            JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);
            return signedJWT.verify(verifier);
        } catch (JOSEException exception) {
            throw new AuthorizationException("invalid JWT token");
        }
    }

    public static boolean verifyExpirationDate(SignedJWT signedJWT) {
        JWTClaimsSet jwtClaimsSet = JwtUtil.getJwtClaimsSet(signedJWT);
        Date expirationTime = jwtClaimsSet.getExpirationTime();
        return new Date().before(expirationTime);
    }
}
