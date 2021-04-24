package edu.stevens.cs594.chat.domain;

import java.util.List;

public interface IMessageDAO {
	
	public static class MessageExn extends Exception {
		private static final long serialVersionUID = 1L;
		public MessageExn (String msg) {
			super(msg);
		}
	}
	
	public List<Message> getMessages();
	
	public Message getMessage (long id) throws MessageExn;
	
	public long addMessage (Message t);
	
	public void deleteMessage (long id);
	
	public void deleteMessages ();
	
}
