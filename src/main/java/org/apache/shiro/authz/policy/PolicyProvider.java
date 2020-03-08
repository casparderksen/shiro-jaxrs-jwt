package org.apache.shiro.authz.policy;

import org.apache.shiro.util.Initializable;

/**
 * A {@code PolicyProvider} is a service that provides {@link Policy} definitions.
 * Realms may implement this interface for exposing their authorization policy,
 * or use {@code PolicyProvider} for externalizing policy definitions.
 */
public interface PolicyProvider extends Initializable {

    Policy getPolicy();
}
