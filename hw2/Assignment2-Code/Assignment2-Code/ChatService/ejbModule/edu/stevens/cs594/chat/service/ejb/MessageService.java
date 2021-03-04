package edu.stevens.cs594.chat.service.ejb;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.annotation.security.DeclareRoles;
import javax.annotation.security.RolesAllowed;
import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.security.enterprise.SecurityContext;
import javax.security.enterprise.identitystore.PasswordHash;

import edu.stevens.cs594.chat.domain.IMessageDAO;
import edu.stevens.cs594.chat.domain.IMessageFactory;
import edu.stevens.cs594.chat.domain.IRoleDAO;
import edu.stevens.cs594.chat.domain.IRoleFactory;
import edu.stevens.cs594.chat.domain.IUserDAO;
import edu.stevens.cs594.chat.domain.IUserDAO.UserExn;
import edu.stevens.cs594.chat.domain.IUserFactory;
import edu.stevens.cs594.chat.domain.Message;
import edu.stevens.cs594.chat.domain.MessageDAO;
import edu.stevens.cs594.chat.domain.MessageFactory;
import edu.stevens.cs594.chat.domain.Role;
import edu.stevens.cs594.chat.domain.RoleDAO;
import edu.stevens.cs594.chat.domain.RoleFactory;
import edu.stevens.cs594.chat.domain.User;
import edu.stevens.cs594.chat.domain.UserDAO;
import edu.stevens.cs594.chat.domain.UserFactory;
import edu.stevens.cs594.chat.service.dto.MessageDto;
import edu.stevens.cs594.chat.service.dto.RoleDto;
import edu.stevens.cs594.chat.service.dto.UserDto;
import edu.stevens.cs594.chat.service.dto.util.MessageDtoFactory;
import edu.stevens.cs594.chat.service.dto.util.RoleDtoFactory;
import edu.stevens.cs594.chat.service.dto.util.UserDtoFactory;
import edu.stevens.cs594.chat.service.ejb.ChatDomainProducer.ChatDomain;
import edu.stevens.cs594.chat.service.ejb.OneTimePassword.OtpAuth;
import edu.stevens.cs594.chat.service.messages.Messages;

/**
 * Session Bean implementation class UserService
 */
@Stateless(name = "MessageServiceBean")

// Declare the roles for RBAC: admin, moderator and poster.
@DeclareRoles({ "admin", "moderator", "poster" })

public class MessageService implements IMessageServiceLocal, IMessageServiceRemote {

	public static final String PASSWORD_HASHING_ALGORITHM = "SHA-256";

	public static final String CHARSET = "UTF-8";

	public static final String ISSUER = "Stevens Institute of Technology";

	@SuppressWarnings("unused")
	private Logger logger = Logger.getLogger(MessageService.class.getCanonicalName());

	private IUserFactory userFactory;

	private UserDtoFactory userDtoFactory;

	private IRoleFactory roleFactory;

	private RoleDtoFactory roleDtoFactory;

	private IUserDAO userDAO;

	private IRoleDAO roleDAO;

	private IMessageDAO messageDAO;

	private IMessageFactory messageFactory;

	private MessageDtoFactory messageDtoFactory;

	/**
	 * Default constructor.
	 */
	public MessageService() {
		roleFactory = new RoleFactory();
		userFactory = new UserFactory();
		messageFactory = new MessageFactory();
		userDtoFactory = new UserDtoFactory();
		roleDtoFactory = new RoleDtoFactory();
		messageDtoFactory = new MessageDtoFactory();
	}

	/*
	 * Inject a security context for programmatic authentication and authorization
	 */
	@Inject
	private SecurityContext securityContext;

	/*
	 * Inject an implementation of the password hash algorithm
	 */
	@Inject
	private PasswordHash passwordHash;

	/*
	 * Inject an entity manager to interface with the database
	 */
	@Inject
	@ChatDomain
	private EntityManager em;

	@PostConstruct
	private void initialize() {
		userDAO = new UserDAO(em);
		roleDAO = new RoleDAO(em);
		messageDAO = new MessageDAO(em);

		/*
		 * Here is an example of how to configure properties of the password hash
		 * algorithm. Make sure these are consistent
		 * with @DatabaseIdentityStoreDefinition in AppConfig in the ChatWebApp.
		 */
		Map<String, String> hashParams = new HashMap<String, String>();
		hashParams.put("Pbkdf2PasswordHash.Iterations", "3072");
		hashParams.put("Pbkdf2PasswordHash.Algorithm", "PBKDF2WithHmacSHA512");
		hashParams.put("Pbkdf2PasswordHash.SaltSizeBytes", "64");
		passwordHash.initialize(hashParams);
	}

	@Override
	public void clearDatabase() {
		messageDAO.deleteMessages();
		userDAO.deleteUsers();
		roleDAO.deleteRoles();
	}

	private String addUser (UserDto dto, OtpAuth otpAuth) throws MessageServiceExn {
		/*
		 * Add user record with hashed password. The secret for the OTP auth should be 
		 * saved in the user record. Return the OTP auth URI, which will be displayed 
		 * as a QR code.
		 * 
		 * The otpAuth may be null (for a test user, for whom we do not do 2FA).
		 */
		
		try {
			String username = dto.getUsername();
			String password = dto.getPassword();
			if (password == null || password.isEmpty()) {
				throw new MessageServiceExn(Messages.admin_user_bad_password);
			}
			
			/*
			 * set the encoded password hash to be set in the database (use passwordHash).
			 */
			String hashedPassword = passwordHash.generate(password.toCharArray());
			
			String secret = null;
			// if not a test user, set secret from otpAuth
			if (otpAuth != null) { 
				secret = otpAuth.getSecretBase32();
			};
			
			User user = userFactory.createUser(username, hashedPassword, secret, dto.getName());
			userDAO.addUser(user);
			
			// add the roles specified in the DTO to the user object (use role.addUser)
			for(String role : dto.getRoles()) {
				Role r = roleDAO.getRole(role);
				r.addUser(user);
			}
			
			userDAO.sync();
	        
	        return (otpAuth != null) ? otpAuth.getKeyUri() : null;        

		} catch (UserExn e) {
			throw new MessageServiceExn(Messages.admin_user_duplicate);
		}
	}

	@Override
	// restrict to admin
	@RolesAllowed("admin")
	public String addUser(UserDto dto) throws MessageServiceExn {
		OtpAuth otpAuth = null;
		/*
		 * TODO Generate OTP authorization (see OneTimePassword)
		 */

		return addUser(dto, otpAuth);
	}

	@Override
	// restrict to admin
	@RolesAllowed("admin")
	public String addTestUser(UserDto dto) throws MessageServiceExn {
		return addUser(dto, null);
	}

	@Override
	// restrict to admin
	@RolesAllowed("admin")
	public void editUser(UserDto dto) {
		try {
			User user = userDAO.getUser(dto.getUsername());
			if (user != null) {
				user.setName(dto.getName());

				if (dto.getPassword() != null && !dto.getPassword().isEmpty()) {
					String hashedPassword = passwordHash.generate(dto.getPassword().toCharArray());
					/*
					 * set the encoded password hash to be set in the database (use
					 * passwordHash).
					 */

					user.setPassword(hashedPassword);
				}

				Collection<Role> toRemove = new ArrayList<Role>();
				for (Role role : user.getRoles()) {
					toRemove.add(role);
				}
				user.getRoles().removeAll(toRemove);
				for (String rolename : dto.getRoles()) {
					Role role = roleDAO.getRole(rolename);
					role.addUser(user);
				}

				userDAO.sync();

			}
		} catch (UserExn e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}

	@Override
	public List<RoleDto> getRoles() {
		List<Role> roles = roleDAO.getRoles();
		List<RoleDto> dtos = new ArrayList<RoleDto>();
		for (Role role : roles) {
			dtos.add(roleDtoFactory.createRoleDto(role));
		}
		return dtos;
	}

	@Override
	// restrict to admin
	@RolesAllowed("admin")
	public void addRole(RoleDto dto) {
		Role role = roleFactory.createRole();
		role.setRoleName(dto.getRolename());
		role.setDescription(dto.getDisplayName());
		roleDAO.addRole(role);
	}

	@Override
	public List<UserDto> getUsers() {
		List<User> users = userDAO.getUsers();
		List<UserDto> dtos = new ArrayList<UserDto>();
		for (User user : users) {
			dtos.add(userDtoFactory.createUserDto(user));
		}
		return dtos;
	}

	@Override
	public UserDto getUser(String username) throws MessageServiceExn {
		try {
			User user = userDAO.getUser(username);
			UserDto dto = userDtoFactory.createUserDto(user);
			return dto;
		} catch (UserExn e) {
			throw new MessageServiceExn(Messages.admin_user_nosuch);
		}
	}

	@Override
	public List<MessageDto> getMessages() {
		List<Message> messages = messageDAO.getMessages();
		List<MessageDto> dtos = new ArrayList<MessageDto>();
		for (Message user : messages) {
			dtos.add(messageDtoFactory.createMessageDto(user));
		}
		return dtos;
	}

	@Override
	// restrict to poster
	@RolesAllowed("poster")
	public long addMessage(MessageDto dto) {
		String loggedInUser = null;
		/*
		 * TODO get the username of the logged-in user (use the security context)
		 */

		if (!loggedInUser.equals(dto.getSender())) {
			throw new IllegalStateException("Poster of message is inconsistent with message metadata.");
		}
		Message message = messageFactory.createMessage(dto.getSender(), dto.getText(), dto.getTimestamp());
		return messageDAO.addMessage(message);
	}

	@Override
	// restrict to moderator
	@RolesAllowed("moderator")
	public void deleteMessage(long id) {
		messageDAO.deleteMessage(id);
	}

	@Override
	public void checkOtp(String username, Long otpCode) throws MessageServiceExn {
		// Look up user with user DAO and check the supplied OTP code
		try {
			User user = userDAO.getUser(username);
			boolean validOtp = false;
			/*
			 * TODO check that the provided OTP code matches what is in the user record,
			 * using current time. See OneTimePassword.
			 */

			if (!validOtp) {
				throw new MessageServiceExn(Messages.login_invalid_code);
			}
		} catch (UserExn e) {
			throw new MessageServiceExn(Messages.admin_user_nosuch);

		}
	}

}
