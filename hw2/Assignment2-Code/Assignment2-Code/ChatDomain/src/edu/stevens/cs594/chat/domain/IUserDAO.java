package edu.stevens.cs594.chat.domain;

import java.util.List;


public interface IUserDAO {
	
	public static class UserExn extends Exception {
		private static final long serialVersionUID = 1L;
		public UserExn (String msg) {
			super(msg);
		}
	}
	
	public List<User> getUsers();

	public User getUser (String username) throws UserExn;
	
	public void addUser (User user) throws UserExn;
	
	public void deleteUsers ();
	
	public void sync();
	
}
