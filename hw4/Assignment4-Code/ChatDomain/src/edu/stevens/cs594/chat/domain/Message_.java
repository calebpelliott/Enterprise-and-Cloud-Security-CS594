package edu.stevens.cs594.chat.domain;

import java.util.Date;
import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value="Dali", date="2015-02-23T19:18:59.728-0500")
@StaticMetamodel(Message.class)
public class Message_ {
	public static volatile SingularAttribute<Message, Long> id;
	public static volatile SingularAttribute<Message, String> text;
	public static volatile SingularAttribute<Message, String> sender;
	public static volatile SingularAttribute<Message, Date> timestamp;
}
