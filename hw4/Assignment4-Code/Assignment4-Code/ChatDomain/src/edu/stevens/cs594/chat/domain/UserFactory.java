package edu.stevens.cs594.chat.domain;


public class UserFactory implements IUserFactory {

	@Override
	public User createUser(String username, String password, String otpSecret, String name) throws IUserDAO.UserExn {
			User u = new User();
			u.setUsername(username);
			u.setPassword(password);
			u.setOtpSecret(otpSecret);
			u.setName(name);
			return u;
	}
	
}
