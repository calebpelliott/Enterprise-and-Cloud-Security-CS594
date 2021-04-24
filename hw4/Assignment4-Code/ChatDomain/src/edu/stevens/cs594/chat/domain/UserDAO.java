package edu.stevens.cs594.chat.domain;

import java.util.List;
import java.util.logging.Logger;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

public class UserDAO implements IUserDAO {

	private EntityManager em;
	
	public UserDAO(EntityManager em) {
		this.em = em;
	}

	@SuppressWarnings("unused")
	private Logger logger = Logger.getLogger(UserDAO.class.getCanonicalName());

	@Override
	public List<User> getUsers() {
		TypedQuery<User> query = em.createNamedQuery("SearchUsers", User.class);
		return query.getResultList();
	}
	
	@Override
	public User getUser(String username) throws UserExn {
		User u = em.find(User.class, username);
		if (u == null) {
			throw new UserExn("User not found: username = " + username);
		} else {
			return u;
		}
	}

	@Override
	public void addUser(User user) throws UserExn {
		String username = user.getUsername();
		Query query = em.createNamedQuery("CountUserByUsername").setParameter("username", username);
		Long numExisting = (Long) query.getSingleResult();
		if (numExisting < 1) {
			em.persist(user);
			em.flush();
		} else {
			throw new UserExn("Insertion: User with username (" + username + ") already exists.");
		}
	}

	@Override
	public void deleteUsers() {
		Query q = em.createNamedQuery("DeleteUsers");
		q.executeUpdate();
	}
	
	@Override
	/**
	 * Push outputs to the database (so JDBC commands for identity store will pick up changes)
	 */
	public void sync() {
		em.flush();
	}

}
