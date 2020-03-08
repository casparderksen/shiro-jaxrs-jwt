package com.acme.permissions.service;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.policy.Policy;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.jwt.JwtPrincipal;
import org.apache.shiro.realm.jwt.JwtRealm;

import java.security.Principal;
import java.util.*;

public class PermissionsService {

    public Set<Permission> getJwtPermissions(Principal principal) {
        if (principal instanceof JwtPrincipal) {
            Set<String> roles = ((JwtPrincipal) principal).getRoles();
            return getJwtPermissions(roles);
        }
        return Collections.emptySet();
    }

    private Set<Permission> getJwtPermissions(Set<String> roles) {
        Set<Permission> permissions = new HashSet<>();
        Optional<Policy> policyOptional = getJwtPolicy();
        if (policyOptional.isPresent()) {
            Policy policy = policyOptional.get();
            for (String role : roles) {
                if (policy.roleExists(role)) {
                    permissions.addAll(policy.getPermissions(role));
                }
            }
        }
        return permissions;
    }

    private Optional<Policy> getJwtPolicy() {
        SecurityManager securityManager = SecurityUtils.getSecurityManager();
        Collection<Realm> realms = ((RealmSecurityManager) securityManager).getRealms();
        for (Realm realm : realms) {
            if (realm instanceof JwtRealm) {
                return Optional.of(((JwtRealm) realm).getPolicy());
            }
        }
        return Optional.empty();
    }
}
