package edu.stevens.cs594.chat.test;

import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.annotation.security.RunAs;
import javax.ejb.LocalBean;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;

import edu.stevens.cs594.chat.domain.Role;
import edu.stevens.cs594.chat.service.dto.RoleDto;
import edu.stevens.cs594.chat.service.dto.UserDto;
import edu.stevens.cs594.chat.service.dto.util.RoleDtoFactory;
import edu.stevens.cs594.chat.service.dto.util.UserDtoFactory;
import edu.stevens.cs594.chat.service.ejb.IMessageService.MessageServiceExn;
import edu.stevens.cs594.chat.service.ejb.IMessageServiceLocal;

/**
 * Session Bean implementation class TestBean
 */
@Singleton
@LocalBean
@Startup

// run with "admin" permissions (to access MessageService)
@RunAs("admin")
public class InitBean {
	
	public static final String ADMINISTRATOR = Role.ROLE_ADMIN;;
	public static final String MODERATOR = Role.ROLE_MODERATOR;
	public static final String POSTER = Role.ROLE_POSTER;
	
	private static Logger logger = Logger.getLogger(InitBean.class.getCanonicalName());

	/**
	 * Default constructor.
	 */
	public InitBean() {
	}
	
	@Inject
	private IMessageServiceLocal messageService;
	
	@PostConstruct
	private void init() {
		
		logger.info("Your name here: Caleb Elliott");

		/*
		 * This is unnecessary, the database tables are dropped and recreated
		 * every time we deploy, see persistence.xml in ChatDomain.
		 */
		// messageService.clearDatabase();
		
		UserDtoFactory userDtoFactory = new UserDtoFactory();

		RoleDtoFactory roleDtoFactory = new RoleDtoFactory();
		
		/*
		 * Put your initialization logic here. Use the logger to display testing output in the server logs.
		 * Make sure to initialize the roles database!
		 * Use the list of roles specified in the Role entity class.
		 */

		try {
			
			for (int ix=0; ix < Role.INIT_ROLE_NAMES.length; ix++) {
				RoleDto role = roleDtoFactory.createRoleDto();
				role.setRolename(Role.INIT_ROLE_NAMES[ix]);
				role.setDisplayName(Role.INIT_ROLE_DISPLAY_NAMES[ix]);
				messageService.addRole(role);
			}

			// Map the admin role to this principal for initialization (@RunAs)
			UserDto admin = userDtoFactory.createUserDto();
			admin.setUsername("admin");
			admin.setPassword("abc123");
			admin.setName("Administrator");
			admin.getRoles().add(ADMINISTRATOR);
			logger.info("Adding user admin");
			messageService.addTestUser(admin);
			
			UserDto joe = userDtoFactory.createUserDto();
			joe.setUsername("joe");
			joe.setPassword("abc123");
			joe.setName("Joe Smith");
			joe.getRoles().add(ADMINISTRATOR);
			logger.info("Adding user joe");
			messageService.addTestUser(joe);
			
			UserDto jane = userDtoFactory.createUserDto();
			jane.setUsername("jane");
			jane.setPassword("xyz789");
			jane.setName("Jane Doe");
			jane.getRoles().add(MODERATOR);
			jane.getRoles().add(POSTER);
			logger.info("Adding user jane");
			messageService.addTestUser(jane);
			
			UserDto john = userDtoFactory.createUserDto();
			john.setUsername("john");
			john.setPassword("foobar!");
			john.setName("John Doe");
			john.getRoles().add(POSTER);
			logger.info("Adding user john");
			messageService.addTestUser(john);
			
			// TODO add more testing
			
		} catch (MessageServiceExn e) {
			throw new IllegalStateException("Failed to add user record.", e);
		} 
			
	}
	
}
