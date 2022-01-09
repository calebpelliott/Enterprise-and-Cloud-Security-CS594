package edu.stevens.cs594.chat.domain;


public interface IUserFactory {
	
	public User createUser(String username, String password, String otpSecret, String name) throws IUserDAO.UserExn;

}
