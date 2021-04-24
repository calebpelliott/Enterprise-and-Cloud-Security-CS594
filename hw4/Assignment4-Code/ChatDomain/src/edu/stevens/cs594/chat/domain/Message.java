package edu.stevens.cs594.chat.domain;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.*;

/**
 * Entity implementation class for Entity: Message
 *
 */
@Entity

@NamedQueries({
	@NamedQuery(
			name="SearchMessages",
			query="select m from Message m"),
	@NamedQuery(
			name="DeleteMessages",
			query="delete from Message m"),
})

@Table(name="MESSAGE")

public class Message implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	public static final int MESSAGE_LENGTH = 60;
	
	@Id
	@GeneratedValue
	private long id;
	
	@Column(length = MESSAGE_LENGTH)
	private String text;
	
	@Column(length = User.USER_NAME_LENGTH)
	private String sender;

	@Temporal(TemporalType.DATE)
	private Date timestamp;

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}
	
	public String getText() {
		return text;
	}

	public void setText(String text) {
		this.text = text;
	}

	public Date getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Date timestamp) {
		this.timestamp = timestamp;
	}

	public String getSender() {
		return sender;
	}

	public void setSender(String sender) {
		this.sender = sender;
	}

	public Message() {
		super();
	}
   
}
