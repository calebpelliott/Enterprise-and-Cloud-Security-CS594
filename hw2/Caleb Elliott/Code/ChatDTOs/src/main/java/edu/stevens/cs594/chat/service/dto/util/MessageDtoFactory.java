package edu.stevens.cs594.chat.service.dto.util;

import edu.stevens.cs594.chat.domain.Message;
import edu.stevens.cs594.chat.service.dto.MessageDto;
import edu.stevens.cs594.chat.service.dto.ObjectFactory;

public class MessageDtoFactory {
	
	ObjectFactory factory;
	
	public MessageDtoFactory() {
		factory = new ObjectFactory();
	}
	
	public MessageDto createMessageDto() {
		return factory.createMessageDto();
	}
	
	public MessageDto createMessageDto(Message m) {
		MessageDto d = factory.createMessageDto();
		d.setId(m.getId());
		d.setSender(m.getSender());
		d.setText(m.getText());
		d.setTimestamp(m.getTimestamp());
		return d;
	}

}
