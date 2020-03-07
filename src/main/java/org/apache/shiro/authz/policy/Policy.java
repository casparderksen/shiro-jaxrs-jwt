package org.apache.shiro.authz.policy;

import org.apache.shiro.authz.Permission;

import java.util.Set;

/**
 * A {@code Policy} provides a way for using external role definitions in a realm.
 */
public interface Policy {

    boolean roleExists(String role);

    Set<Permission> getPermissions(String role);
}