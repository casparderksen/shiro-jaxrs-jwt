package com.acme.ping.adapter.rest;

import org.apache.shiro.authz.annotation.RequiresPermissions;

import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@ApplicationScoped
@Path("/ping")
@Produces(MediaType.APPLICATION_JSON)
public class PingResource {

    @RequiresPermissions("ping:read")
    @GET
    public String ping() {
        return "hello ping!";
    }
}