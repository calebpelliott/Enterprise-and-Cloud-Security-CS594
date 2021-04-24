package edu.stevens.cs594.chat.domain;

import java.util.Date;


public interface IMessageFactory {
	
	public Message createMessage (String sender, String text, Date timestamp);
	
}
