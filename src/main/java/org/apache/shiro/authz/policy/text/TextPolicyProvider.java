package org.apache.shiro.authz.policy.text;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.authz.policy.Policy;
import org.apache.shiro.authz.policy.PolicyProvider;
import org.apache.shiro.realm.text.TextConfigurationRealm;

import java.util.Collections;
import java.util.Set;

public class TextPolicyProvider extends TextConfigurationRealm implements PolicyProvider {

    @Override
    public Policy getPolicy() {
        return new PolicyAdapter();
    }

    /**
     * Adaptor realm with {@link Policy} interface. Must be inner class to access protected members.
     */
    private final class PolicyAdapter implements Policy {

        @Override
        public boolean roleExists(String role) {
            return TextPolicyProvider.this.roleExists(role);
        }

        @Override
        public Set<Permission> getPermissions(String roleName) {
            SimpleRole role = getRole(roleName);
            if (role == null) {
                return Collections.emptySet();
            }
            return role.getPermissions();
        }
    }
}
