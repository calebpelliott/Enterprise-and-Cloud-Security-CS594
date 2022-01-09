package edu.stevens.cs594.chat.service.messages;

import javax.xml.bind.annotation.XmlRootElement;

public interface IMessageService {
	
	
	@XmlRootElement
	public static class MessageRep {
		
		protected String text;
		protected String sender;

		public String getText() {
			return text;
		}
		public void setText(String text) {
			this.text = text;
		}
		public String getSender() {
			return sender;
		}
		public void setSender(String sender) {
			this.sender = sender;
		}
		
	}
	
	public long addMessage(MessageRep message);
		
}
