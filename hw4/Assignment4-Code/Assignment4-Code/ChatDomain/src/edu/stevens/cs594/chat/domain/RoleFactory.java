package edu.stevens.cs594.chat.domain;

public class RoleFactory implements IRoleFactory {

	@Override
	public Role createRole() {
		return new Role();
	}

}
