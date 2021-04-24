package edu.stevens.cs594.chat.domain;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

public class MessageDAO implements IMessageDAO {
	
	public MessageDAO (EntityManager em) {
		this.em = em;
	}
	
	private EntityManager em;

	@Override
	public List<Message> getMessages() {
		TypedQuery<Message> query = em.createNamedQuery("SearchMessages", Message.class);
		return query.getResultList();
	}
	
	@Override
	public Message getMessage(long id) throws MessageExn {
		Message t = em.find(Message.class, id);
		if (t == null) {
			throw new MessageExn("Missing treatment: id = " + id);
		} else {
			return t;
		}
	}

	@Override
	public long addMessage(Message t) {
		em.persist(t);
		return t.getId();
	}
	
	@Override
	public void deleteMessage(long id) {
		Message m = em.find(Message.class, id);
		if (m != null) {
			em.remove(m);
		} else {
			throw new IllegalArgumentException("No message with id "+id);
		}
	}

	@Override
	public void deleteMessages() {
		Query q = em.createNamedQuery("DeleteMessages");
		q.executeUpdate();
	}

}
