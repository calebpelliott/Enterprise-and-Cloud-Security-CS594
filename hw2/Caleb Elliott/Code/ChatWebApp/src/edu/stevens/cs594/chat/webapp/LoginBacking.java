package edu.stevens.cs594.chat.webapp;

import static javax.security.enterprise.AuthenticationStatus.SEND_FAILURE;

import java.security.Principal;
import java.util.List;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.SecurityContext;
import javax.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.stevens.cs594.chat.domain.Role;
import edu.stevens.cs594.chat.service.dto.RoleDto;
import edu.stevens.cs594.chat.service.ejb.IMessageService.MessageServiceExn;
import edu.stevens.cs594.chat.service.ejb.IMessageServiceLocal;
import edu.stevens.cs594.chat.service.messages.Messages;

@Named("loginBacking")
@ViewScoped
public class LoginBacking extends BaseBacking {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3210700134869332261L;

	private static Logger logger = Logger.getLogger(LoginBacking.class.getCanonicalName());
	
	@Inject
	private SecurityContext securityContext;
	
	private String username;

	private String password;

	private String otpCode;

	/*
	 * Note: JSF requires that RoleDto be serializable. Since RoleDto is a
	 * generated JAXB class, we have to specify in the XSD (as a JAXB extension)
	 * that the generated class should implement Serializable.
	 */
	private List<RoleDto> roles;

	private String selectedRole;

	@Inject
	private IMessageServiceLocal loginService;

	public String getUsername() {
		if (username == null) {
			Principal prin = securityContext.getCallerPrincipal();
			if (prin != null)
				return prin.getName();
			else
				return null;
		} else {
			return username;
		}
	}

	public void setUsername(String name) {
		this.username = name;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getOtpCode() {
		return otpCode;
	}

	public void setOtpCode(String otpCode) {
		this.otpCode = otpCode;
	}

	public String getSelectedRole() {
		return selectedRole;
	}

	public void setSelectedRole(String role) {
		this.selectedRole = role;
	}

	public List<RoleDto> getRoles() {
		return roles;
	}

	@PostConstruct
	public void init() {
		roles = loginService.getRoles();
	}

	public String login() {
		
		HttpServletRequest request = getWebRequest();
		HttpServletResponse response = getWebResponse();
		
		Credential credential = new UsernamePasswordCredential(username, new Password(password));	
		
		// Authenticate using the security context.
		// Use AuthenticationParameters.withParams() to pass credential.
		AuthenticationStatus status = securityContext.authenticate(request, response, AuthenticationParameters.withParams().credential(credential));

		logger.info("Result of authentication: " + status);
		
		if (status.equals(SEND_FAILURE)) {
			// Never leave a comment like this in production code!
			logger.info("Failed to authenticate "+username+" with password "+password);
			addMessage(Messages.login_invalid_credentials);
			return null;				
		}

		logger.info("Principal: "+getUsername());
		
		/*
		 * Check the one-time password (OTP) required for 2FA
		 */
		try {
			Long code = null;
			if (otpCode != null && !otpCode.isEmpty()) {
				code = (long) Integer.parseInt(otpCode);				
			}
			/*
			 * check the input otp with what is in the user record (see loginService)
			 */
			loginService.checkOtp(username, code);
			
		} catch (NumberFormatException | MessageServiceExn e) {
			addMessage(Messages.login_malformed_code);
			logout();
			return null;
		}

		logger.info("Selected login role: "+selectedRole);
		
		/*
		 * Use the security context to check that the selected role is valid for this user.
		 * this.selectedRole is the role name for the role selected in the form.
		 */
		boolean validRole = securityContext.isCallerInRole(selectedRole);
		
		if (!validRole) {
			addMessage(Messages.login_invalid_role);
			logout();
			return null;
		}
		if (Role.ROLE_ADMIN.equals(selectedRole)) {
			return Navigation.NAV_ADMIN_LOGGED_IN;
		} else if (Role.ROLE_MODERATOR.equals(selectedRole)) {
			return Navigation.NAV_MODERATOR_LOGGED_IN;
		} else if (Role.ROLE_POSTER.equals(selectedRole)) {
			return Navigation.NAV_POSTER_LOGGED_IN;
		} else {
			throw new IllegalStateException("Unrecognized selectedRole " + selectedRole);
		}

	}
	
	public void logout() {
		try {
			getWebRequest().logout();
		} catch (ServletException e) {
			throw new IllegalStateException("Problem logging out", e);
		}
	}


	public boolean isLoggedIn() {
		// use security context to check if a user is logged in
		boolean loggedIn = securityContext.getCallerPrincipal() != null; 
		return loggedIn;
	}

}
