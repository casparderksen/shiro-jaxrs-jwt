package com.acme.permissions.adapter.rest;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.realm.jwt.JwtPrincipal;

import javax.enterprise.context.ApplicationScoped;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;
import java.util.Collections;
import java.util.Set;

@ApplicationScoped
@Path("/permissions")
@Produces(MediaType.APPLICATION_JSON)
public class PermissionsResource {

    @RequiresPermissions("permissions:read")
    @GET
    public JsonArray getPermissions(@Context SecurityContext securityContext) {
        Set<Permission> permissions = getPermissions(securityContext.getUserPrincipal());
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        permissions.forEach(permission -> arrayBuilder.add(permission.toString()));
        return arrayBuilder.build();
    }

    private Set<Permission> getPermissions(Principal principal) {
        if (principal instanceof JwtPrincipal) {
            return ((JwtPrincipal) principal).getPermissions();
        }
        return Collections.emptySet();
    }
}