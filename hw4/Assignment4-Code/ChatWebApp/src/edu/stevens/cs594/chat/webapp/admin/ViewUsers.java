package edu.stevens.cs594.chat.webapp.admin;

import java.util.List;

import javax.annotation.PostConstruct;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;

import edu.stevens.cs594.chat.service.dto.UserDto;
import edu.stevens.cs594.chat.service.ejb.IMessageServiceLocal;
import edu.stevens.cs594.chat.webapp.BaseBacking;
import edu.stevens.cs594.chat.webapp.Navigation;

@Named("viewUsersBacking")
@ViewScoped
public class ViewUsers extends BaseBacking {

	private static final long serialVersionUID = -733113325524128462L;
	
	@Inject
	IMessageServiceLocal securityService;

	/*
	 * This returns the current cursor in the list of users.
	 */
	private UserDto user;

	public UserDto getUser() {
		return user;
	}

	/*
	 * The list of users themselves, from which the cursor is selected.
	 */
	private List<UserDto> users;

	public List<UserDto> getUsers() {
		return users;
	}

	public void setUsers(List<UserDto> users) {
		this.users = users;
	}

	@PostConstruct
	private void init() {
		users = securityService.getUsers();
	}

	public String addUser() {
		/*
		 * A separate screen allows user info to be entered.
		 */
		return Navigation.NAV_ADMIN_ADD_USER;
	}

}
