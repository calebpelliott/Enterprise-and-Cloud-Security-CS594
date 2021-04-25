package edu.stevens.cs594.chat.domain;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;


/**
 * Entity implementation class for Entity: Role
 * 
 * This should really be called Group, because the database associates users with groups.
 * Authorization is based on roles (defined in web.xml in ChatWebApp).
 * Groups are mapped to roles in glassfish-web.xml in ChatWebApp.
 * 
 */
@Entity
@NamedQueries({
	@NamedQuery(
			name = "SearchRoles", 
			query = "select r from Role r order by r.roleName"),
	@NamedQuery(
			name = "DeleteRoles",
			query = "delete from Role r"),
})
@Table(name = "ROLES")
public class Role implements Serializable {

	public final static String ROLE_ADMIN = "admin";
	public final static String ROLE_MODERATOR = "moderator";
	public final static String ROLE_POSTER = "poster";
	
	public final static String ROLE_ADMIN_DESCRIPTION = "admin.role.admin";
	public final static String ROLE_MODERATOR_DESCRIPTION = "admin.role.moderator";
	public final static String ROLE_POSTER_DESCRIPTION = "admin.role.poster";
	
	public final static String[] INIT_ROLE_NAMES = {
		ROLE_ADMIN, 
		ROLE_MODERATOR,
		ROLE_POSTER, 
	};
	
	public final static String[] INIT_ROLE_DISPLAY_NAMES = {
		ROLE_ADMIN_DESCRIPTION,
		ROLE_MODERATOR_DESCRIPTION,
		ROLE_POSTER_DESCRIPTION,
	};
	
	public static final int ROLE_NAME_LENGTH = 20;
	
	public static final int ROLE_DESCRIPTION_LENGTH = 20;

	private static final long serialVersionUID = 1L;

	@Id
	@Column(length = ROLE_NAME_LENGTH, nullable = false)
	private String roleName;
	
	@Column(length = ROLE_DESCRIPTION_LENGTH)
	private String description;

	@ManyToMany
	@JoinTable(name = "USERS_ROLES", 
		joinColumns = @JoinColumn(name = "ROLENAME", referencedColumnName = "ROLENAME"), 
		inverseJoinColumns = @JoinColumn(name = "USERNAME", referencedColumnName = "USERNAME"))
	private Collection<User> users;

	public String getRoleName() {
		return roleName;
	}

	public void setRoleName(String roleName) {
		this.roleName = roleName;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Collection<User> getUsers() {
		return users;
	}

	public void setUsers(Collection<User> users) {
		this.users = users;
	}

	public void addUser(User user) {
		if (user != null && !users.contains(user)) {
			users.add(user);
			user.addRole(this);
		}
	}

	public void removeUser(User user) {
		if (user != null && users.contains(user)) {
			users.remove(user);
			user.removeRole(this);
		}
	}
	
	public Role() {
		super();
		users = new ArrayList<User>();
	}

}
