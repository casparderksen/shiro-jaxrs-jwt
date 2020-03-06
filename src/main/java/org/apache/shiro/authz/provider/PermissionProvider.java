package org.apache.shiro.authz.provider;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.util.Initializable;

import java.util.Collection;

/**
 * A {@code PermissionProvider} provides a way for using external role definitions in a realm.
 */
public interface PermissionProvider extends Initializable {

    boolean roleExists(String role);

    Collection<Permission> getPermissions(String role);
}
