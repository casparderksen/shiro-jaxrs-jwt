package org.apache.shiro.authz.policy;

import org.apache.shiro.util.Initializable;

/**
 * A {@code PolicyProvider} is a service that provides {@link Policy} definitions.
 */
public interface PolicyProvider extends Initializable {

    Policy getPolicy();
}
