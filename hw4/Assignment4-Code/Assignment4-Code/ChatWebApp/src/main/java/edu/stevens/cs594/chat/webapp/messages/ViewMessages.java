package edu.stevens.cs594.chat.webapp.messages;

import java.security.Principal;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.security.enterprise.SecurityContext;

import edu.stevens.cs594.chat.service.dto.MessageDto;
import edu.stevens.cs594.chat.service.dto.util.MessageDtoFactory;
import edu.stevens.cs594.chat.service.ejb.IMessageServiceLocal;
import edu.stevens.cs594.chat.webapp.BaseBacking;

@Named("messagesBacking")
@ViewScoped
public class ViewMessages extends BaseBacking {

	private static final long serialVersionUID = -1983439889541606510L;
	
	@SuppressWarnings("unused")
	private static Logger logger = Logger.getLogger(ViewMessages.class.getCanonicalName());

	@Inject
	private SecurityContext securityContext;
	
	private String username;
	
	/*
	 * For new messages, when the user is a poster.
	 */
	private String text;
	
	/*
	 * List of messages.  Each line has a boolean for deletion by a moderator.
	 */
	private List<MessageDto> messages;
	
	public String getUsername() {
		return username;
	}

	public List<MessageDto> getMessages() {
		return this.messages;
	}

	public String getText() {
		return text;
	}

	public void setText(String text) {
		this.text = text;
	}

	@Inject
	private IMessageServiceLocal messageService;
	
	private MessageDtoFactory messageDtoFactory = new MessageDtoFactory();
	
	/**
	 * Refresh the messages from the database.
	 */
	public void refreshMessages() {
		messages = messageService.getMessages();
	}
	
	/**
	 * Invoked by poster to post a new message.
	 */
	public void postMessage() {
		MessageDto message = messageDtoFactory.createMessageDto();
		message.setSender(username);
		message.setTimestamp(new Date(System.currentTimeMillis()));
		message.setText(text);
		messageService.addMessage(message);
		text = "";
		refreshMessages();
	}
	
	/**
	 * Invoked by moderator to delete a message.
	 */
	public void deleteMessage(long id) {
		messageService.deleteMessage(id);		
		refreshMessages();
	}
	
	@PostConstruct
	private void init() {
		// TOD set this.username to be the currently logged-in user, and refresh messages.
		username = securityContext.getCallerPrincipal().getName();
		refreshMessages();
	}

}
