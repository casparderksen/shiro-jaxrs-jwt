package org.apache.shiro.authz.policy;

/**
 * Interface for components that may be configured with a {@link PolicyProvider}.
 */
public interface PolicyProviderAware {

    void setPolicyProvider(PolicyProvider policyProvider);
}
