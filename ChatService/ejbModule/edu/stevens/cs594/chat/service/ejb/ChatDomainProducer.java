package edu.stevens.cs594.chat.service.ejb;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.ejb.LocalBean;
import javax.ejb.Stateless;
import javax.enterprise.inject.Disposes;
import javax.enterprise.inject.Produces;
import javax.inject.Qualifier;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

/**
 * Session Bean implementation class PatientProducer
 */
@Stateless
@LocalBean
public class ChatDomainProducer {

    /**
     * Default constructor. 
     */
    public ChatDomainProducer() {
    }
    
    @Qualifier  
    @Retention(RetentionPolicy.RUNTIME)  
    @Target({ElementType.METHOD, ElementType.FIELD, ElementType.PARAMETER})  
    public @interface ChatDomain {}
    
    @PersistenceContext(unitName="ChatDomain")
    EntityManager em;
    
    @Produces @ChatDomain
    public EntityManager chatDomainProducer() {
    	return em;
    }
    
    public void chatDomainDispose(@Disposes @ChatDomain EntityManager em) {
    	em.close();
    }

}
