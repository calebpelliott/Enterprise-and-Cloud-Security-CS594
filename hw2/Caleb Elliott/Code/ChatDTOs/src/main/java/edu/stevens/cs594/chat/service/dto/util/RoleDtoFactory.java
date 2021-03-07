package edu.stevens.cs594.chat.service.dto.util;

import edu.stevens.cs594.chat.domain.Role;
import edu.stevens.cs594.chat.service.dto.ObjectFactory;
import edu.stevens.cs594.chat.service.dto.RoleDto;

public class RoleDtoFactory {
	
	ObjectFactory factory;
	
	public RoleDtoFactory() {
		factory = new ObjectFactory();
	}
	
	public RoleDto createRoleDto() {
		return factory.createRoleDto();
	}
	
	public RoleDto createRoleDto(Role r) {
		RoleDto d = factory.createRoleDto();
		d.setRolename(r.getRoleName());
		d.setDisplayName(r.getDescription());
		return d;
	}

}
