package edu.stevens.cs594.chat.service.web.rest.resources;

import java.net.URI;
import java.security.Principal;
import java.util.logging.Logger;

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import edu.stevens.cs594.chat.service.messages.IMessageService;
import edu.stevens.cs594.chat.service.messages.IMessageService.MessageRep;

@Path("/forum")
@RequestScoped
public class MessageResource {
	
	final static Logger logger = Logger.getLogger(MessageResource.class.getCanonicalName());
	
    @Context
    private UriInfo uriInfo;
    
    @Context
    private SecurityContext securityContext;

    /**
     * Default constructor. 
     */
    public MessageResource() {
    }
    
    @Inject
    private IMessageService messageService;

	@POST
	@Path("messages")
	@Consumes("application/xml")
	@RolesAllowed("poster")
	public Response addMessage(MessageRep message) {
		Principal prin = securityContext.getUserPrincipal();
		String name = (prin == null) ? null : prin.getName();
		logger.info("Successfully authenticated poster: "+name);
		
		long id = messageService.addMessage(message);
		
		UriBuilder ub = uriInfo.getAbsolutePathBuilder().path("{id}");
		URI url = ub.build(id);
		return Response.created(url).build();
	}
    
    
}