package edu.stevens.cs594.chat.domain;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

public class RoleDAO implements IRoleDAO {

	private EntityManager em;
	
	public RoleDAO(EntityManager em) {
		this.em = em;
	}

	@Override
	public List<Role> getRoles() {
		TypedQuery<Role> query = em.createNamedQuery("SearchRoles", Role.class);
		return query.getResultList();
	}

	@Override
	public Role getRole(String rolename) {
		Role r = em.find(Role.class, rolename);
		if (r == null) {
			throw new IllegalArgumentException("Missing role "+rolename);
		} else {
			return r;
		}
	}

	@Override
	public void addRole(Role role) {
		em.persist(role);
	}

	@Override
	public void deleteRoles() {
		Query q = em.createNamedQuery("DeleteRoles");
		q.executeUpdate();
	}	

}
