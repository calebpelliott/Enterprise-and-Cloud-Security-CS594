package edu.stevens.cs594.chat.service.ejb;

import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.security.enterprise.SecurityContext;
import javax.transaction.Transactional;

import edu.stevens.cs594.chat.domain.IMessageDAO;
import edu.stevens.cs594.chat.domain.IMessageFactory;
import edu.stevens.cs594.chat.domain.Message;
import edu.stevens.cs594.chat.domain.MessageDAO;
import edu.stevens.cs594.chat.domain.MessageFactory;
import edu.stevens.cs594.chat.service.ejb.ChatDomainProducer.ChatDomain;
import edu.stevens.cs594.chat.service.messages.IMessageService;
import edu.stevens.cs594.util.DateUtils;

/**
 * CDI Bean to support programmatic use of messaging system
 */
@RequestScoped
@Transactional
// RBAC not defined for CDI beans (but can be defined for resources)
// @DeclareRoles({"admin","moderator","poster"})
public class MessageService implements IMessageService {
	
	public static final String CHARSET = "UTF-8";
	
	public static final String ISSUER = "Stevens Institute of Technology";
	
	@SuppressWarnings("unused")
	private Logger logger = Logger.getLogger(MessageService.class.getCanonicalName());

	
	private IMessageDAO messageDAO;
	
	private IMessageFactory messageFactory;
	
	/**
	 * Default constructor.
	 */
	public MessageService() {
		messageFactory = new MessageFactory();
	}
	
	/*
	 * Inject a security context for programmatic authentication and authorization
	 */
	@Inject 
	private SecurityContext securityContext;
	
	/*
	 * Inject an entity manager to interface with the database
	 */
	@Inject @ChatDomain
	private EntityManager em;

	@PostConstruct
	private void initialize() {
		messageDAO = new MessageDAO(em);
	}

	@Override
	public long addMessage(MessageRep messageRep) {
		Message message = messageFactory.createMessage(messageRep.getSender(), messageRep.getText(), DateUtils.now());
		return messageDAO.addMessage(message);
	}

}