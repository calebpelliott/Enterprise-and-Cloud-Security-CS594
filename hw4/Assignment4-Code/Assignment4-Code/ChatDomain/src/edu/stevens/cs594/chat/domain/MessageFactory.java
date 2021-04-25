package edu.stevens.cs594.chat.domain;

import java.util.Date;

public class MessageFactory implements IMessageFactory {

	@Override
	public Message createMessage(String sender, String text, Date timestamp) {
		Message message = new Message();
		message.setSender(sender);
		message.setText(text);
		message.setTimestamp(timestamp);
		return message;
	}

}
