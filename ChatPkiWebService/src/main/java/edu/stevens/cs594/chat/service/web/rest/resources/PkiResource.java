package edu.stevens.cs594.chat.service.web.rest.resources;

import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import edu.stevens.cs594.chat.service.ejb.IPkiService;
import edu.stevens.cs594.chat.service.ejb.IPkiService.GenClientCertRequest;
import edu.stevens.cs594.chat.service.ejb.IPkiService.GenClientCertResponse;

@Path("/certs")
@RequestScoped
public class PkiResource {
	
	final static Logger logger = Logger.getLogger(PkiResource.class.getCanonicalName());
	
    @Context
    private SecurityContext securityContext;

    /**
     * Default constructor. 
     */
    public PkiResource() {
    }
    
    @Inject
    private IPkiService pkiService;
    

	@POST
	@Consumes("application/xml")
	@Produces("application/xml")
	@RolesAllowed("poster")
	public Response genClientCert(GenClientCertRequest request) {
		
		String name = securityContext.getUserPrincipal().getName();
		logger.info("Successfully authenticated Web client: " + name);

		try {
			GenClientCertResponse clientCert = pkiService.genClientCert(name, request);
			logger.info("Returning client cert in PEM format.");
			return Response.ok(clientCert, MediaType.APPLICATION_XML_TYPE).build();
		} catch (GeneralSecurityException e) {
			logger.log(Level.SEVERE, "Security exception while generating client cert.", e);
			return Response.serverError().build();
		}		
	}

    
}