package org.apache.shiro.realm.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authz.AuthorizationException;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

public class JwtVerifier {

    /**
     * Verify whether JWT token is signed and that the signature is valid
     * @param signedJWT the token
     * @param rsaPublicKey public key
     * @return true iff valid
     */
    public static boolean verifyJwtToken(SignedJWT signedJWT, RSAPublicKey rsaPublicKey) {
        try {
            JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);
            return signedJWT.verify(verifier);
        } catch (JOSEException exception) {
            throw new AuthorizationException(exception);
        }
    }

    /**
     * Verify whether JWT token is not expired
     * @param signedJWT the token
     * @return true iff expiration date set and not expired
     */
    public static boolean verifyExpirationDate(SignedJWT signedJWT) {
        try {
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            Date expirationTime = jwtClaimsSet.getExpirationTime();
            if (expirationTime == null) {
                return false;
            }
            return new Date().before(expirationTime);
        } catch (ParseException exception) {
            throw new AuthorizationException(exception);
        }
    }
}
