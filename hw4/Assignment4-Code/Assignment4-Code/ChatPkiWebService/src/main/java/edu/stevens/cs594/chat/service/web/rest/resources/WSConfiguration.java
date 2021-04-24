package edu.stevens.cs594.chat.service.web.rest.resources;

import java.util.HashSet;
import java.util.Set;

import javax.annotation.security.DeclareRoles;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@ApplicationScoped
@ApplicationPath("/resources")
@DeclareRoles({ "poster" }) 

// TODO add annotations for BASIC authentication, using database from Assignment 2


public class WSConfiguration extends Application {

    public Set<Class<?>> getClasses() {
        Set<Class<?>> s = new HashSet<Class<?>>();
        s.add(PkiResource.class);
        return s;
    }

}