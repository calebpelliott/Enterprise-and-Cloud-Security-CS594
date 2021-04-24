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
 * specify custom forms authentication with login page /login.xhtml, login error page /loginError.xhtml
 */
@CustomFormAuthenticationMechanismDefinition(
loginToContinue = @LoginToContinue(
loginPage = "/login.html",
errorPage = "/login-error.html"))
/*
 * specify authentication and authorization using a database (see spec for guidance).
 * Set password hashing algorithm parameters to be consistent with MessageService.
 */
@DatabaseIdentityStoreDefinition(
dataSourceLookup = "jdbc/cs594",
callerQuery = "select password from users where username = ?",
groupsQuery = "select rolename from users_roles where username = ?",
priority=30,
hashAlgorithm = PasswordHash.class,
hashAlgorithmParameters = {
"Pbkdf2PasswordHash.Iterations=3072",
"Pbkdf2PasswordHash.Algorithm=PBKDF2WithHmacSHA512",
"Pbkdf2PasswordHash.SaltSizeBytes=64"})


@ApplicationScoped		
public class AppConfig {

}
