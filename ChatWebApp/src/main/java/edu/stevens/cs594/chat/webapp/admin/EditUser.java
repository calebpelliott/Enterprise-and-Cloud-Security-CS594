package edu.stevens.cs594.chat.webapp.admin;

import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;

import edu.stevens.cs594.chat.service.dto.RoleDto;
import edu.stevens.cs594.chat.service.dto.UserDto;
import edu.stevens.cs594.chat.service.dto.util.UserDtoFactory;
import edu.stevens.cs594.chat.service.ejb.IMessageService.MessageServiceExn;
import edu.stevens.cs594.chat.service.ejb.IMessageServiceLocal;
import edu.stevens.cs594.chat.service.messages.Messages;
import edu.stevens.cs594.chat.webapp.BaseBacking;
import edu.stevens.cs594.chat.webapp.Navigation;

@Named("editUserBacking")
@ViewScoped
public class EditUser extends BaseBacking {

	private static final long serialVersionUID = -6498472821445783075L;

	@SuppressWarnings("unused")
	private static Logger logger = Logger.getLogger(EditUser.class.getCanonicalName());

	/**
	 * The value of this property is provided as a query string parameter and
	 * set by a metadata annotation in the form.
	 */
	private String username;
	
	private boolean valid;
	/*
	 * Edit a user: change name, password and/or security roles.
	 */
	private String password;

	// Roles from the database
	private List<RoleDto> roles;
	
	// Selected roles
	private String[] selectedRoles;
	
	private String name;

	public String getUsername() {
		return username;
	}

	public void setUsername(String userName) {
		this.username = userName;
	}

	public boolean isValid() {
		return valid;
	}

	public void setValid(boolean valid) {
		this.valid = valid;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public List<RoleDto> getRoles() {
		return roles;
	}

	public String[] getSelectedRoles() {
		return selectedRoles;
	}

	public void setSelectedRoles(String[] selectedRoles) {
		this.selectedRoles = selectedRoles;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	/*
	 * This service interacts with the database backend.
	 */
	@Inject
	private IMessageServiceLocal userService;

	private UserDtoFactory userDtoFactory = new UserDtoFactory();
	
	/**
	 * Triggered by receipt of a parameter value identifying the user.
	 */
	public void load() {
		valid = false;
		roles = userService.getRoles();
		try {
			if (username != null) {
				UserDto user = userService.getUser(username);
				password = null;
				name = user.getName();
				Collection<String> rs = user.getRoles();
				selectedRoles = new String[rs.size()];
				int ix = 0;
				for (String r : rs) {
					selectedRoles[ix++] = r;
				}
				valid = true;
			} else {
				addMessage(Messages.admin_user_none);
			}
		} catch (MessageServiceExn e) {
			addMessage(e.getMessageCode());
		}
	}

	/**
	 * This logic is executed to save the changes.
	 */
	public String editUser() {
		if (valid) {
			UserDto user = userDtoFactory.createUserDto();
			user.setUsername(username);
			if (password != null && !password.isEmpty()) {
				user.setPassword(password);
				
			}
			for (String role : selectedRoles) {
				user.getRoles().add(role);
			}
			user.setName(name);
			userService.editUser(user);
			return Navigation.NAV_ADMIN_EDITED_USER;
		} else {
			addMessage(Messages.admin_user_nosuch);
			return null;
		}
	}

}
