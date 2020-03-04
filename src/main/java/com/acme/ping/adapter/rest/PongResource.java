package com.acme.ping.adapter.rest;

import org.apache.shiro.authz.annotation.RequiresPermissions;

import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@ApplicationScoped
@Path("/pong")
@Produces(MediaType.APPLICATION_JSON)
public class PongResource {

    @RequiresPermissions("pong:read")
    @GET
    public String pong() {
        return "hello pong!";
    }
}