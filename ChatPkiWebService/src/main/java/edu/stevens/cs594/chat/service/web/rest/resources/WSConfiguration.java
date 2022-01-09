package edu.stevens.cs594.chat.service.web.rest.resources;

import java.util.HashSet;
import java.util.Set;

import javax.annotation.security.DeclareRoles;
import javax.enterprise.context.ApplicationScoped;
import javax.security.enterprise.authentication.mechanism.http.BasicAuthenticationMechanismDefinition;
import javax.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;
import javax.security.enterprise.identitystore.PasswordHash;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@ApplicationScoped
@ApplicationPath("/resources")
@DeclareRoles({ "poster" }) 

// TOD add annotations for BASIC authentication, using database from Assignment 2
@BasicAuthenticationMechanismDefinition
@DatabaseIdentityStoreDefinition(
dataSourceLookup = "jdbc/cs594",
callerQuery = "select password from users where username = ?",
groupsQuery = "select rolename from users_roles where username = ?",
priority=30,
hashAlgorithm = PasswordHash.class,
hashAlgorithmParameters = {
"Pbkdf2PasswordHash.Iterations=3072",
"Pbkdf2PasswordHash.Algorithm=PBKDF2WithHmacSHA512",
"Pbkdf2PasswordHash.SaltSizeBytes=64"})

public class WSConfiguration extends Application {

    public Set<Class<?>> getClasses() {
        Set<Class<?>> s = new HashSet<Class<?>>();
        s.add(PkiResource.class);
        return s;
    }

}