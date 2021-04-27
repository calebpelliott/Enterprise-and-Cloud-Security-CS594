package edu.stevens.cs594.chat.service.web.rest.resources;

import java.util.HashSet;
import java.util.Set;

import javax.annotation.security.DeclareRoles;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import fish.payara.security.annotations.CertificateAuthenticationMechanismDefinition;
import fish.payara.security.annotations.CertificateIdentityStoreDefinition;

@ApplicationScoped
@ApplicationPath("/resources")

// In realm properties in server, can set common-name-as-principal-name property to be true
// https://docs.payara.fish/enterprise/docs/5.27.0/documentation/payara-server/server-configuration/security/certificate-realm-principal-name.html
// but JAX/RS is taking principal name from cert issuer name????

@DeclareRoles({ "poster" }) 

// TODO Specify certificate realm for authentication, assign group "poster" to successful authebticators
@CertificateAuthenticationMechanismDefinition
@CertificateIdentityStoreDefinition("certificate")
@RolesAllowed("poster")

public class WSConfiguration extends Application {

    public Set<Class<?>> getClasses() {
        Set<Class<?>> s = new HashSet<Class<?>>();
        s.add(MessageResource.class);
        return s;
    }

}