package edu.stevens.cs594.chat.webapp;

import java.io.Serializable;
import java.util.Locale;
import java.util.ResourceBundle;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.component.UIInput;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.stevens.cs594.chat.service.messages.Messages;

public class BaseBacking implements Serializable {
	
	private static final long serialVersionUID = 1819802919748985743L;
	
	public static final String CHARSET = "utf-8";
	
	@Inject
	private FacesContext facesContext;
	
	protected FacesContext getFacesContext() {
		// return FacesContext.getCurrentInstance();
		return facesContext;
	}

	protected ExternalContext getExternalContext() {
		return getFacesContext().getExternalContext();
	}

	protected HttpServletRequest getWebRequest() {
		return (HttpServletRequest) getExternalContext().getRequest();
	}
	
	protected HttpServletResponse getWebResponse() {
		return (HttpServletResponse) getExternalContext().getResponse();
	}
	
	/*
	 * Locale-specific feedback, optionally associated with a UI component.
	 */
	private static ResourceBundle getBundle(FacesContext context) {
		Locale locale = context.getViewRoot().getLocale();
		return ResourceBundle.getBundle(Messages.messagesPath, locale);
	}

	protected static void addMessageToContext(FacesContext context, String clientId, String key) {
		ResourceBundle res = getBundle(context);
		context.addMessage(clientId,  new FacesMessage(res.getString(key)));
	}
	
	protected void addMessage(String clientId, String key) {
		addMessageToContext(getFacesContext(), clientId, key);
	}
	
	protected String getClientId(String id) {
		return getFacesContext().getViewRoot().findComponent(id).getClientId(getFacesContext());
	}
	
	protected void addMessage(String key) {
		addMessage((String)null, key);
	} 
	
	public String getDisplayString(String key) {
		return key == null ? null : getBundle(getFacesContext()).getString(key);
	}
	
	protected static void reportValidationError(FacesContext context, UIComponent component, String key) {
		((UIInput) component).setValid(false);
		addMessageToContext(context, component.getClientId(context), key);
	}
		
}
