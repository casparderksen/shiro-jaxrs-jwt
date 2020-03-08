package org.apache.shiro.authz.service;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.policy.Policy;
import org.apache.shiro.authz.policy.PolicyProvider;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.jwt.JwtPrincipal;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class PermissionsService {

    public Set<Permission> getPermissions(Principal principal) {
        Set<String> roles = getRoles(principal);
        return getPermissions(roles);
    }

    private Set<String> getRoles(Principal principal) {
        if (principal instanceof JwtPrincipal) {
            return ((JwtPrincipal) principal).getRoles();
        }
        return Collections.emptySet();
    }

    private Set<Permission> getPermissions(Set<String> roles) {
        Policy policy = getPolicy();
        if (policy == null) {
            return Collections.emptySet();
        }
        Set<Permission> permissions = new HashSet<>();
        for (String role : roles) {
            if (policy.roleExists(role)) {
                permissions.addAll(policy.getPermissions(role));
            }
        }
        return permissions;
    }

    private Policy getPolicy() {
        SecurityManager securityManager = SecurityUtils.getSecurityManager();
        Collection<Realm> realms = ((RealmSecurityManager) securityManager).getRealms();
        for (Realm realm : realms) {
            if (realm instanceof PolicyProvider) {
                return ((PolicyProvider) realm).getPolicy();
            }
        }
        return null;
    }
}
