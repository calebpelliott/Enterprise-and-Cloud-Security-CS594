package edu.stevens.cs594.chat.webapp;

import static javax.faces.annotation.FacesConfig.Version.JSF_2_3;

import javax.enterprise.context.ApplicationScoped;
import javax.faces.annotation.FacesConfig;
import javax.security.enterprise.authentication.mechanism.http.CustomFormAuthenticationMechanismDefinition;
import javax.security.enterprise.authentication.mechanism.http.LoginToContinue;
import javax.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;
import javax.security.enterprise.identitystore.PasswordHash;

@FacesConfig(version = JSF_2_3)

/*
 * TODO specify custom forms authentication with login page /login.xhtml, login error page /loginError.xhtml
 */

/*
 * TODO specify authentication and authorization using a database (see spec for guidance).
 * Set password hashing algorithm parameters to be consistent with MessageService.
 */
		
public class AppConfig {

}
