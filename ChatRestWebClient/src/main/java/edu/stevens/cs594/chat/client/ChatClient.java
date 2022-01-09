package edu.stevens.cs594.chat.client;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;

import edu.stevens.cs594.chat.service.ejb.IPkiService.GenClientCertRequest;
import edu.stevens.cs594.chat.service.ejb.IPkiService.GenClientCertResponse;
import edu.stevens.cs594.chat.service.messages.IMessageService.MessageRep;

public class ChatClient {
	
	@SuppressWarnings("unused")
	private static final Logger logger = Logger.getLogger(ChatClient.class.getSimpleName());
	
	private String uri;

	private Client client;
	
	
	/**
	 * Return an SSL context that uses the app truststore to authenticate the server.
	 * 
	 * @return
	 * @throws GeneralSecurityException
	 */
	public SSLContext getAuthContext(KeyStore keystore, char[] keystorePassword, KeyStore truststore)
			throws GeneralSecurityException {
		KeyManager[] keyManagers = null;
		TrustManager[] trustManagers = null;

		if (keystore != null) {
			// TOD complete this (init keyManagers with keystore if not null)
			String defaultAlg = KeyManagerFactory.getDefaultAlgorithm();
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(defaultAlg); 
			kmf.init(keystore, keystorePassword);
			keyManagers = kmf.getKeyManagers();
		}

		// TOD complete this (init trustManagers with truststore)
		String defaultAlg = TrustManagerFactory.getDefaultAlgorithm();
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(defaultAlg); 
		tmf.init(truststore);
		trustManagers = tmf.getTrustManagers();

		SSLContext context = SSLContext.getInstance("TLS");
		context.init(keyManagers, trustManagers, null);

		return context;
	}
	
	public SSLContext getAuthContext(KeyStore truststore) throws GeneralSecurityException {
		return getAuthContext(null, null, truststore);
	}
	
	/**
	 * Construct a Web service client for getting a client cert from the online CA.
	 * @param baseUri
	 * @param truststore
	 * @param username
	 * @param password
	 * @throws GeneralSecurityException
	 */
	public ChatClient(URI baseUri, KeyStore truststore, String username, char[] password) throws GeneralSecurityException {
		
		/*
		 * SSL context just verifies server cert is signed by root CA.
		 * This is used to verify online CA, which will issue client cert based on CSR.
		 */
		SSLContext sslContext = getAuthContext(truststore);
		
		/*
		 * We won't bother doing host name verification.  
		 */
		HostnameVerifier hostnameVerifier = new HostnameVerifier() {
			@Override
			public boolean verify(String arg0, SSLSession arg1) {
				return true;
			} 
		};
		
		/*
		 * Configure basic authentication for "registration" (CA that provides client cert)
		 */
		HttpAuthenticationFeature basicFeature = HttpAuthenticationFeature.basic(username, new String(password));
		// TOD configure client to do BASIC authentication.
		this.client = ClientBuilder.newBuilder().sslContext(sslContext).register(basicFeature).build();
		
		UriBuilder ub = UriBuilder.fromUri(baseUri);
		this.uri = ub.path("resources").path("certs").build().toString();;
	}
	
	/**
	 * Configure a Web service client for posting messages to the chat server.
	 * @param baseUri
	 * @param keystore
	 * @param keystorePassword
	 * @param truststore
	 * @throws GeneralSecurityException
	 */
	public ChatClient(URI baseUri, KeyStore keystore, char[] keystorePassword, KeyStore truststore) throws GeneralSecurityException {
		
		/*
		 * SSL context here use client cert in keystore to authenticate to chat server.
		 */
		SSLContext sslContext = getAuthContext(keystore, keystorePassword, truststore);

		/*
		 * We won't bother doing host name verification.  
		 */
		HostnameVerifier hostnameVerifier = new HostnameVerifier() {
			@Override
			public boolean verify(String arg0, SSLSession arg1) {
				return true;
			} 
		};
				
		/*
		 * Configue cert-based authentication for posting messages
		 */
		// TOD configure client to do certificate-based authentication.
		this.client = ClientBuilder.newBuilder().sslContext(sslContext).build();
		
		UriBuilder ub = UriBuilder.fromUri(baseUri);
		this.uri = ub.path("resources").path("forum").path("messages").build().toString();;
	}
	
	
	/**
	 * Request a client cert (use basic authentication at the CA)
	 */
	public GenClientCertResponse register(GenClientCertRequest certRequest) {
		try {
			WebTarget target = client.target(uri);
			Invocation.Builder request = target.request(MediaType.APPLICATION_XML_TYPE);
			Response response = request.post(Entity.xml(certRequest));

			if (response.getStatus() != Response.Status.OK.getStatusCode()) {
				logger.info("Unexpected response from server: " + response.getStatus());
				return null;
			}
			
			GenClientCertResponse responseEntity = response.readEntity(GenClientCertResponse.class);
			return responseEntity;
		} catch (Exception e) {
			logger.info("Exception with Web service request/response: " + e);
			return null;
		}
	}
	
	/**
	 * Post a message to the forum (authenticate using our client cert)
	 */
	public int postMessage(String sender, String text) {
		try {
			MessageRep message = new MessageRep();
			message.setSender(sender);
			message.setText(text);

			WebTarget target = client.target(uri);
			Invocation.Builder request = target.request();
			Response response = request.post(Entity.xml(message));
			return response.getStatus();
		} catch (Exception e) {
			logger.info("Exception with Web service request/response: " + e);
			return Response.Status.FORBIDDEN.getStatusCode();
		}
	}
	
	
}
