package edu.stevens.cs594.chat.service.dto.util;

import edu.stevens.cs594.chat.domain.Role;
import edu.stevens.cs594.chat.domain.User;
import edu.stevens.cs594.chat.service.dto.ObjectFactory;
import edu.stevens.cs594.chat.service.dto.UserDto;

public class UserDtoFactory {
	
	ObjectFactory factory;
	
	public UserDtoFactory() {
		factory = new ObjectFactory();
	}
	
	public UserDto createUserDto() {
		return factory.createUserDto();
	}
	
	public UserDto createUserDto(User u) {
		UserDto d = factory.createUserDto();
		d.setUsername(u.getUsername());
		d.setName(u.getName());
		for (Role role : u.getRoles()) {
			d.getRoles().add(role.getRoleName());
		}
		return d;
	}

}
