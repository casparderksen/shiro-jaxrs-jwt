package org.apache.shiro.realm.jwt;

import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.policy.Policy;
import org.apache.shiro.authz.policy.PolicyProvider;
import org.apache.shiro.authz.policy.text.IniPolicyProvider;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.filter.jwt.JwtFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Set;

/**
 * Realm for adding access control based on JWT tokens.
 * Configure the <code>publicKey</code> property for validating tokens.
 * Configure {@link JwtFilter} for extracting JWT tokens from HTTP requests and performing the login to the realm.
 */
public class JwtRealm extends AuthorizingRealm implements PolicyProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtRealm.class);

    private Policy policy;
    private PolicyProvider policyProvider;
    private RSAPublicKey rsaPublicKey;

    public JwtRealm() {
        // Support JwtAuthenticationToken for authentication
        setAuthenticationTokenClass(JwtAuthenticationToken.class);
        // Do not cache tokens that should expire fast
        setCachingEnabled(false);
    }

    public void setPublicKey(byte[] publicKey) {
        try {
            rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException exception) {
            throw new ConfigurationException("invalid publicKey", exception);
        }
    }

    public void setPolicyProvider(PolicyProvider policyProvider) {
        this.policyProvider = policyProvider;
    }

    @Override
    protected void onInit() {
        if (policyProvider == null) {
            policyProvider = new IniPolicyProvider();
            policyProvider.init();
        }
        policy = policyProvider.getPolicy();
    }

    @Override
    public Policy getPolicy() {
        return policy;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
        // Safe cast because we told the security manager to support JwtAuthenticationToken
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) token;
        JwtPrincipal jwtPrincipal = jwtAuthenticationToken.getPrincipal();

        // Check that principal name is defined
        String name = jwtPrincipal.getName();
        if (name == null) {
            log.warn("token does not specify principal");
            return null;
        } else if (log.isDebugEnabled()) {
            log.debug("authenticating principal {}", name);
        }

        // Check that the token is valid
        SignedJWT signedJWT = jwtAuthenticationToken.getCredentials();
        if (!JwtVerifier.verifyJwtToken(signedJWT, rsaPublicKey)) {
            log.warn("token invalid");
            return null;
        }

        // Check that the token has not expired
        if (!JwtVerifier.verifyExpirationDate(signedJWT)) {
            log.warn("token expired");
            return null;
        }

        // Create and return AuthenticationInfo with JWT token as principal
        return new SimpleAuthenticationInfo(jwtPrincipal, signedJWT, getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // Get JWT from principal collection
        JwtPrincipal jwtPrincipal = principals.oneByType(JwtPrincipal.class);
        if (jwtPrincipal == null) {
            log.error("JwtPrincipal not found in principal collection");
            return null;
        }

        // Create AuthorizationInfo with roles from JWT and permissions from realm
        Set<String> roles = jwtPrincipal.getRoles();
        SimpleAuthorizationInfo authzInfo = new SimpleAuthorizationInfo(roles);
        addPermissions(authzInfo, roles);
        jwtPrincipal.setPermissions(authzInfo.getObjectPermissions());
        return authzInfo;
    }

    private void addPermissions(SimpleAuthorizationInfo authzInfo, Collection<String> roles) {
        for (String role : roles) {
            if (policy.roleExists(role)) {
                Collection<Permission> permissions = policy.getPermissions(role);
                authzInfo.addObjectPermissions(permissions);
                if (log.isDebugEnabled()) {
                    log.debug("added permissions from role {}", role);
                }
            }
        }
    }
}