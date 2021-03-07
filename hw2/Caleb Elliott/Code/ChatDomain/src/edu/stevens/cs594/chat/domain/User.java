package edu.stevens.cs594.chat.domain;

import static javax.persistence.FetchType.EAGER;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OrderBy;
import javax.persistence.Table;

/**
 * Entity implementation class for Entity: User
 *
 */
@Entity

@NamedQueries({
	@NamedQuery(
		name="SearchUsers",
		query="select u from User u"),
	@NamedQuery(
		name="CountUserByUsername",
		query="select count(u) from User u where u.username = :username"),
	@NamedQuery(
		name="DeleteUsers",
		query="delete from User u"),
})

@Table(name="USERS")

public class User implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	public static final int USER_NAME_LENGTH = 20;
	
	private static final int HASHED_PASSWORD_LENGTH = 1600;
	
	@Id
	@Column(length=USER_NAME_LENGTH, nullable=false)
	private String username;
	
	@Column(length=HASHED_PASSWORD_LENGTH, nullable=false)
	private String password;
	
	private String otpSecret;
	
	private String name;
	
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getOtpSecret() {
		return otpSecret;
	}

	public void setOtpSecret(String otpSecret) {
		this.otpSecret = otpSecret;
	}


	@ManyToMany(mappedBy = "users", fetch = EAGER)
	@OrderBy
	private List<Role> roles;

	public List<Role> getRoles() {
		return roles;
	}

	protected void setRoles(List<Role> roles) {
		this.roles = roles;
	}
	
	public void addRole(Role role) {
		if (!roles.contains(role)) {
			roles.add(role);
		}
	}
	
	public void removeRole(Role role) {
		roles.remove(role);
	}

	public User() {
		super();
		roles = new ArrayList<Role>();
	}
   
}
