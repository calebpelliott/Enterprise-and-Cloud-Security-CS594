package edu.stevens.cs594.chat.service.ejb;

import java.util.List;

import edu.stevens.cs594.chat.service.dto.MessageDto;
import edu.stevens.cs594.chat.service.dto.RoleDto;
import edu.stevens.cs594.chat.service.dto.UserDto;

public interface IMessageService {
	
	public class MessageServiceExn extends Exception {
		private static final long serialVersionUID = 1L;
		private String messageCode;
		public String getMessageCode() {
			return messageCode;
		}
		public MessageServiceExn (String m) {
			super();
			messageCode = m;
		}
	}
	public class UserNotFoundExn extends MessageServiceExn {
		private static final long serialVersionUID = 1L;
		public UserNotFoundExn (String m) {
			super(m);
		}
	}
	public class MessageNotFoundExn extends MessageServiceExn {
		private static final long serialVersionUID = 1L;
		public MessageNotFoundExn (String m) {
			super(m);
		}
	}
	
	public void clearDatabase();
	
	public List<RoleDto> getRoles();

	public void addRole(RoleDto role);

	public List<UserDto> getUsers();

	public UserDto getUser(String username) throws MessageServiceExn;

	public String addUser(UserDto user) throws MessageServiceExn;

	public String addTestUser(UserDto user) throws MessageServiceExn;

	public void editUser(UserDto user);

	public List<MessageDto> getMessages();

	public long addMessage(MessageDto message);

	public void deleteMessage(long id);
		
	public void checkOtp(String username, Long otpCode) throws MessageServiceExn;

}
