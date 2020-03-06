package org.apache.shiro.jwt;

import com.nimbusds.jwt.SignedJWT;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.realm.text.TextConfigurationRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.CollectionUtils;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Collection;
import java.util.Set;

/**
 * Realm for adding access control based on JWT tokens.
 * Configure the <code>publicKey</code> property for validating tokens.
 * Configure {@link JwtFilter} for extracting JWT tokens from HTTP requests and performing the login to the realm.
 * TODO: composition with policy provider instead of inheriting from TextConfigurationRealm.
 */
@Slf4j
public class JwtRealm extends TextConfigurationRealm {

    @Setter
    private String resourcePath = "classpath:roles.ini";
    private RSAPublicKey rsaPublicKey;

    @SneakyThrows
    public void setPublicKey(byte[] publicKey) {
        rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
    }

    public JwtRealm() {
        // Support JwtAuthenticationToken for authentication
        setAuthenticationTokenClass(JwtAuthenticationToken.class);
        // Do not cache tokens that should expire fast
        setCachingEnabled(false);
    }

    @Override
    protected void onInit() {
        super.onInit();
        Ini ini = Ini.fromResourcePath(resourcePath);
        if (CollectionUtils.isEmpty(ini)) {
            throw new IllegalStateException("Cannot load Ini from resourcePath " + resourcePath);
        }
        processDefinitions(ini);
    }

    private void processDefinitions(Ini ini) {
        Ini.Section rolesSection = ini.getSection(IniRealm.ROLES_SECTION_NAME);
        if (CollectionUtils.isEmpty(rolesSection)) {
            log.warn("No [{}] section defined, cannot assign permissions", IniRealm.ROLES_SECTION_NAME);
        } else {
            log.debug("Processing the [{}] section", IniRealm.ROLES_SECTION_NAME);
            processRoleDefinitions(rolesSection);
        }
    }

    @Override
    protected void processDefinitions() {
        try {
            processRoleDefinitions();
        } catch (ParseException e) {
            String msg = "Unable to parse role definitions.";
            throw new ConfigurationException(msg, e);
        }
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
        // Safe cast because we told the security manager to support JwtAuthenticationToken
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) token;
        String principal = jwtAuthenticationToken.getPrincipal();
        if (log.isDebugEnabled()) {
            log.debug("authenticating principal {}", principal);
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
        return new SimpleAuthenticationInfo(signedJWT, signedJWT, getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // Get JWT from principal collection
        SignedJWT signedJWT = principals.oneByType(SignedJWT.class);
        if (signedJWT == null) {
            log.error("SignedJWT not found in principal collection");
            return null;
        }

        // Create AuthorizationInfo with roles from JWT and permissions from realm
        Set<String> roles = getRoles(signedJWT);
        SimpleAuthorizationInfo authzInfo = new SimpleAuthorizationInfo(roles);
        addPermissions(authzInfo, roles);
        return authzInfo;
    }

    private Set<String> getRoles(SignedJWT signedJWT) {
        try {
            Set<String> roles = JwtParser.getRoles(signedJWT);
            if (roles == null) {
                throw new AuthorizationException("roles claim not specified");
            }
            return roles;
        } catch (ParseException exception) {
            throw new AuthorizationException(exception);
        }
    }

    private void addPermissions(SimpleAuthorizationInfo authzInfo, Collection<String> roles) {
        for (String role : roles) {
            if (roleExists(role)) {
                Collection<Permission> permissions = getRole(role).getPermissions();
                authzInfo.addObjectPermissions(permissions);
                if (log.isDebugEnabled()) {
                    log.debug("added permissions from role {}", role);
                }
            }
        }
    }
}