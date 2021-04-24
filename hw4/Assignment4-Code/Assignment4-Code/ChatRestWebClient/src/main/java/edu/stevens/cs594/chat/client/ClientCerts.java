package edu.stevens.cs594.chat.client;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import edu.stevens.cs594.certgen.CertsService;
import edu.stevens.cs594.crypto.CAUtils;
import edu.stevens.cs594.crypto.PrivateCredential;
import edu.stevens.cs594.util.DateUtils;
import edu.stevens.cs594.util.ExceptionWrapper;
import edu.stevens.cs594.util.FileUtils;
import edu.stevens.cs594.util.Reporter;

@ApplicationScoped
/**
 * Certificate library for REST client, managing its keystore and truststore.  
 * Structured as a CDI bean because it uses functionality
 * of CertsService, which is also injected on the CA server.
 * 
 * @author dduggan
 */
public class ClientCerts {
	
	protected static final Logger logger = Logger.getLogger(ClientCerts.class.getCanonicalName());
	
	/*
	 * Properties in the passwords file.
	 */
	private static final String CLIENT_TRUSTSTORE_PASSWORD = "client.truststore.password";
	
	private static final String CLIENT_KEYSTORE_PASSWORD = "client.keystore.password";
	
	private static final String CLIENT_KEY_PASSWORD = "client.key.password";
		
	
	/*
	 * Aliases for credentials and certificates.
	 */
	
	// CA root certificate for truststore
	public static final String CLIENT_CA_ALIAS = "client-ca";
	
	// Client credential for keystore 
	public static final String CLIENT_CERT_ALIAS = "client-cert";
	
	
	
	/**
	 * Keystore types.
	 */
	private static final String CLIENT_KEYSTORE_TYPE = "JKS";

	private static final String CLIENT_TRUSTSTORE_TYPE = "JKS";
	
		
	private Reporter reporter;
	
	public ClientCerts() {
		reporter = Reporter.createReporter();
	}
	
	private void say(String msg) {
		reporter.say(msg);
	}
	
	@Inject
	private CertsService certsService;
	
	private File keystoreFile;
	
	private File truststoreFile;
	
	private char[] keystorePassword;
	
	private char[] keyPassword;
	
	private char[] truststorePassword;
	
	private KeyStore clientKeyStore;
	
	private KeyStore clientTrustStore;

	
	private void loadPasswords(File passwordFile) throws IOException {
		Properties properties = new Properties();
		Reader in = FileUtils.openInputCharFile(passwordFile);
		properties.load(in);
		in.close();

		String password = properties.getProperty(CLIENT_KEYSTORE_PASSWORD);
		if (password == null) {
			say("No keystore password provided: " + CLIENT_KEYSTORE_PASSWORD);
			throw new IOException("Failed to provide keystoreFile password.");
		} else {
			keystorePassword = password.toCharArray();
		}

		password = properties.getProperty(CLIENT_KEY_PASSWORD);
		if (password == null) {
			say("No key password provided: " + CLIENT_KEY_PASSWORD);
			throw new IOException("Failed to provide key password.");
		} else {
			keyPassword = password.toCharArray();
		}

		password = properties.getProperty(CLIENT_TRUSTSTORE_PASSWORD);
		if (password == null) {
			say("No truststore password provided: " + CLIENT_TRUSTSTORE_PASSWORD);
			throw new IOException("Failed to provide truststoreFile password.");
		} else {
			truststorePassword = password.toCharArray();
		}
	}
	
	public void initKeystores(File passwordsFile, File keystoreFile, File truststoreFile) throws IOException, GeneralSecurityException {
				
		this.keystoreFile = keystoreFile;
		
		this.truststoreFile = truststoreFile;
		
		loadPasswords(passwordsFile);
		
		clientKeyStore = certsService.load(this.keystoreFile, keystorePassword, CLIENT_KEYSTORE_TYPE);
		
		clientTrustStore = certsService.load(this.truststoreFile, truststorePassword, CLIENT_TRUSTSTORE_TYPE);
	}
	
	public KeyStore getKeyStore() {
		return clientKeyStore;
	}
	
	public char[] getKeyPassword() {
		return keyPassword;
	}
	
	public KeyStore getTrustStore() {
		return clientTrustStore;
	}

	
	/*
	 * These operations are taken from the Certificate Manager in a previous assignment.
	 */
	
	/**
	 * Get the fingerprint of a cryptographic value (cert, public key, etc).
	 */
	public static byte[] getFingerprint(byte[] cert) throws GeneralSecurityException {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			byte[] digest = md.digest(cert);
			return digest;
		} catch (NoSuchAlgorithmException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}

	public static byte[] getCertFingerprint(X509Certificate cert) throws GeneralSecurityException {
		return getFingerprint(cert.getEncoded());
	}
	
	public static byte[] getCertFingerprint(byte[] cert) throws GeneralSecurityException {
		return getFingerprint(cert);
	}
	
	private static String digits = "0123456789abcdef";

	/**
	 * Return length many bytes of the passed in byte array as a hex string.
	 */
	public static String toHex(byte[] data, int length) {
		if (data == null) {
			return null;
		}
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i != length; i++) {
			int v = data[i] & 0xff;
			buf.append(digits.charAt(v >> 4));
			buf.append(digits.charAt(v & 0xf));
		}
		return buf.toString();
	}
	
	/**
	 * Return the passed in byte array as a hex string.
	 */
	public static String toHex(byte[] data) {
		return toHex(data, data.length);
	}
	
	/**
	 * Display hex string as sequence of pairs of hex digits.
	 */
	public static String displayHex(byte[] b) {
		if (b == null) {
			return null;
		}
		String s = toHex(b);
		int len = s.length();
		if (s.length() <= 2 || s.length() % 2 != 0) {
			throw new IllegalArgumentException("Trivial edge case in displayHex.");
		}
		StringBuilder sb = new StringBuilder();
		sb.append(s.charAt(0));
		sb.append(s.charAt(1));
		for (int i = 2; i < len-1; i+=2) {
			sb.append(':');
			sb.append(s.charAt(i));
			sb.append(s.charAt(i+1));
		}
		return sb.toString();
	}	

	private void showCredentialInfo(String certName, PrivateCredential credential) throws GeneralSecurityException {
		say("================================================================================");
		say(certName);
		byte[] fp = getFingerprint(certsService.fromPrivateKey(credential.getPrivateKey()).getEncoded());
		say("SHA1: " + displayHex(fp));
		for (X509Certificate certificate : credential.getCertificate()) {
			say("--------------------------------------------------------------------------------");
			showCertificateInfo(certificate);
		}
		say("");
	}
	
	private void showCertificateInfo(X509Certificate certificate) throws GeneralSecurityException {
		say(String.format("Issuer: %s", certificate.getIssuerX500Principal().getName()));
		say(String.format("Subject: %s", certificate.getSubjectX500Principal().getName()));
		say("Serial number: "+certificate.getSerialNumber().toString(16));
		say("SHA1: " + displayHex(getCertFingerprint(certificate)));
		Date before = certificate.getNotBefore();
		Date after = certificate.getNotAfter();
		say(String.format("Valid from %s to %s", DateUtils.dateTimeFormat(before), DateUtils.dateTimeFormat(after)));
	}
	
	public void showClientCert() {
		try {
			PrivateCredential clientCredential = certsService.getCredential(clientKeyStore, CLIENT_CERT_ALIAS,
					keyPassword);
			showCredentialInfo("Client Cert: ", clientCredential);
		} catch (Exception e) {
			logger.log(Level.SEVERE, "Unable to show client credential.", e);
			return;
		}

		try {
			X509Certificate caCert = certsService.getCertificate(clientTrustStore, CLIENT_CA_ALIAS);
			say("CA Cert:");
			showCertificateInfo(caCert);
			say("");
		} catch (Exception e) {
			logger.log(Level.SEVERE, "Unable to show client certificate.", e);
			return;
		}
	}

	
	/**
	 * Import certifcate for root CA.
	 * @throws GeneralSecurityException 
	 */
	public void importCaCert(File certFile) throws IOException, GeneralSecurityException {
		Certificate cert = CertsService.internCertificate(certFile);
		clientTrustStore.setCertificateEntry(CLIENT_CA_ALIAS, cert);
		certsService.save(truststoreFile, truststorePassword, CLIENT_TRUSTSTORE_PASSWORD, clientTrustStore);
	}
	
	/**
	 * Generate initial v1 self-signed cert for a client.
	 */
	public void genClientRoot(String clientName, long duration) throws Exception {
		if (clientName == null) {
			reporter.error("Missing client distinguished name.");
			return;
		}
		
		long id = certsService.getRandomLong();
		X500Name clientDn = CAUtils.toX500Name(clientName);
		KeyPair keyPair = certsService.generateKeyPair();
		
		/*
		 * Create self-signed v1 cert and save in client keystore
		 */
		X509Certificate cert = CAUtils.createClientRootCert(id, clientDn, keyPair, duration);
		X509Certificate[] chain = { cert };
		clientKeyStore.setKeyEntry(CLIENT_CERT_ALIAS, keyPair.getPrivate(), keyPassword, chain);
		
		/*
		 * Save the updated keystore
		 */
		certsService.save(keystoreFile, keystorePassword, CLIENT_KEYSTORE_TYPE, clientKeyStore);
	}

	/**
	 * Generate client CSR signed by their private key
	 */
	public String genClientCSR(String clientDns) throws GeneralSecurityException {

		
		try {
			PKCS10CertificationRequest csr = null;

			/*
			 * TODO generate a CSR signed by the client's private key
			 */

			
			return CertsService.extern(csr);
		} catch (UnrecoverableKeyException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (KeyStoreException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (NoSuchAlgorithmException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
	/**
	 * Import a client cert generated by a CSR
	 */
	public void importClientCert(byte[] clientCert) throws GeneralSecurityException {
		
		try {
			
			/*
			 * TODO import the cert and store it in the clientKeyStore
			 */

			
			/*
			 * Save the updated keystore
			 */
			certsService.save(keystoreFile, keystorePassword, CLIENT_KEYSTORE_TYPE, clientKeyStore);
			
		} catch (UnrecoverableKeyException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (KeyStoreException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (NoSuchAlgorithmException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}

	}

}
