package edu.stevens.cs594.chat.domain;

import javax.annotation.Generated;
import javax.persistence.metamodel.CollectionAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value="Dali", date="2019-02-12T17:48:49.213-0500")
@StaticMetamodel(Role.class)
public class Role_ {
	public static volatile SingularAttribute<Role, String> roleName;
	public static volatile SingularAttribute<Role, String> description;
	public static volatile CollectionAttribute<Role, User> users;
}
