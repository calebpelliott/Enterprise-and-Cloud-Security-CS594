package edu.stevens.cs594.certgen;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.enterprise.context.Dependent;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
//import edu.stevens.cs594.crypto.SecurityParams;

import edu.stevens.cs594.crypto.PrivateCredential;
import edu.stevens.cs594.util.ExceptionWrapper;
import edu.stevens.cs594.util.FileUtils;
import edu.stevens.cs594.util.StringUtils;

@Dependent
public class CertsService {
	
	/**
	 * Invoke with arguments.
	 */
	
	private static final Logger logger = Logger.getLogger(CertsService.class.getCanonicalName());	
	
	
	/*
	 * Properties in the passwords file.
	 */
	public static final String OFFLINE_KEYSTORE_PASSWORD = "offline.keystore.password";
	public static final String OFFLINE_KEY_PASSWORD = "offline.key.password";

	public static final String APP_TRUSTSTORE_PASSWORD = "app.truststore.password";
	public static final String APP_KEYSTORE_PASSWORD = "app.keystore.password";
	public static final String APP_KEY_PASSWORD = "app.key.password";
	
	public static final String AS_TRUSTSTORE_PASSWORD = "appserver.truststore.password";
	public static final String AS_KEYSTORE_PASSWORD = "appserver.keystore.password";
	public static final String AS_KEY_PASSWORD = "appserver.key.password";
	
	/*
	 * Properties in the distinguished names file.
	 */
	public static final String CA_ROOT = "ca.root";
	
	public static final String CA_ONLINE = "ca.online";
	
	public static final String SERVER_CERT = "server.cert";
	
	
	/*
	 * Aliases for credentials and certificates.
	 */
	
	// CA root (in the offline keystore)
	public static final String CA_ROOT_ALIAS = "ca-root";
	
	// For current server SSL cert (in the app server keystore)
	public static final String SERVER_CERT_ALIAS = "s1as";
	
	// Online CA for app client certs (in the online app keystore).
	public static final String CA_ONLINE_CERT_ALIAS = "ca-online";
	
	// Client cert provided to app (alias in client keystore).
	public static final String CLIENT_CERT_ALIAS = "client-cert";
	
	
	
	/*
	 * Default durations.
	 */
	public static final int ONE_YEAR = 365 * 24;
	
	public static final long CA_ROOT_DURATION = 10 * ONE_YEAR;
	
	public static final long CA_ONLINE_CERT_DURATION = 5 * ONE_YEAR;
		
	public static final long CLIENT_CERT_DURATION = ONE_YEAR;
	
	public static final long SERVER_CERT_DURATION = ONE_YEAR;
	
	/**
	 * Keystore types.
	 */
	// For root CA key.
	public static final String ROOT_KEYSTORE_TYPE = "PKCS12";
	
	// Online keystores and truststores
	public static final String APP_KEYSTORE_TYPE = "PKCS12";

	public static final String APP_TRUSTSTORE_TYPE = "BKS";
	
	public static final String APP_SERVER_KEYSTORE_TYPE = "JKS";
	
	public static final String APP_SERVER_TRUSTSTORE_TYPE = "JKS";
	
	public static final String CLIENT_KEYSTORE_TYPE = "PKCS12";

	/**
	 * The certificate manager makes some assumptions about the organization of the space where keystores and
	 * truststores are managed.
	 * 
	 * Directories:
	 */	
	public static final String OFFLINE_DIR = "certs-offline";
	
	public static final String ONLINE_DIR = "certs-online";
	
	public static final String BACKUP_DIR = "certs-backup";
	
	public static final String BACKUP_OFFLINE_DIR = BACKUP_DIR + File.separatorChar + OFFLINE_DIR;
	
	public static final String BACKUP_ONLINE_DIR = BACKUP_DIR + File.separatorChar + ONLINE_DIR;
		
	/**
	 * Files:
	 */	
	public static final String ROOT_KEYSTORE_FILENAME = "caroot.p12";
	
	// private static final String ENCRYPTION_KEYSTORE_FILENAME = "keystore-encryption.p12";
	
	public static final String APP_KEYSTORE_FILENAME = "keystore.p12";
	
	public static final String APP_TRUSTSTORE_FILENAME = "truststore.bks";
	
	public static final String APP_SERVER_KEYSTORE_FILENAME = "keystore.jks";
	
	public static final String APP_SERVER_TRUSTSTORE_FILENAME = "cacerts.jks";
	
	public static final String PASSWORDS_FILENAME = "passwords.properties";
	
	public static final String NAMES_FILENAME = "names.properties";
	
	
	public CertsService() {
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			logger.log(Level.SEVERE, "Unable to find random algorithm SHA1PRNG.", e);
		}
	}
	
	
	/**
	 * Save the contents of the keystores after an update.
	 */
	public void save(File store, char[] password, String keystoreType, KeyStore keystore) throws GeneralSecurityException {
		try {
			OutputStream out = new FileOutputStream(store);
			keystore.store(out, password);
			out.close();
		} catch (KeyStoreException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (CertificateException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (NoSuchAlgorithmException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (FileNotFoundException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (IOException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} 
	}
	
	/**
	 * Load an individual keystore (from CredentialManager).
	 */
	public KeyStore load(File store, char[] password, String keystoreType) throws GeneralSecurityException {
		try {
			KeyStore keystore = KeyStore.getInstance(keystoreType);
			if (!store.exists()) {
				logger.info("Store does not exist, initializing " + store.getAbsolutePath());
				keystore.load(null, null);
			} else {
				InputStream in = new FileInputStream(store);
				keystore.load(in, password);
				in.close();
			}
			return keystore;
		} catch (KeyStoreException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (CertificateException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (NoSuchAlgorithmException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (FileNotFoundException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (IOException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}

	private X509Certificate[] toX509Certificates(Certificate[] certificates) {
		if (certificates == null) {
			return null;
		}
		X509Certificate[] x509certificates = new X509Certificate[certificates.length];
		for (int i=0; i<certificates.length; i++) {
			x509certificates[i] = (X509Certificate)certificates[i];
		}
		return x509certificates;
	}
	
	/**
	 * Retrieve a credential from the keystore (from CredentialManager).
	 */
	public PrivateCredential getCredential(KeyStore keystore, String alias, char[] password) throws GeneralSecurityException {
		PrivateKey key = (PrivateKey) keystore.getKey(alias, password);
		X509Certificate[] chain = toX509Certificates(keystore.getCertificateChain(alias));
		
		// TOD get key and cert chain from the keystore
		if (chain == null) {
			throw new IllegalArgumentException("Missing certificate for credential "+alias);
		}
		
		return new PrivateCredential(chain, key, alias);
	}
	
	/**
	 * Retrieve a certificate from a truststore.
	 */
	public X509Certificate getCertificate(KeyStore truststore, String alias) throws GeneralSecurityException {
		Certificate certificate = truststore.getCertificate(alias);
		
		// TOD get certificate from the truststore
		
		if (certificate == null) {
			throw new IllegalStateException("No certificate in the truststore with alias "+alias);
		}
		return (X509Certificate) certificate;
	}
	
	public static final int ASYMMETRIC_KEY_LENGTH = 2048;
	
	// Recommended for X509 & default in BC
	public static final RSAKeyGenParameterSpec RSA_KEY_SPECS = 
			new RSAKeyGenParameterSpec(ASYMMETRIC_KEY_LENGTH, RSAKeyGenParameterSpec.F4);
	
	/**
	 * Create a random RSA key pair.
	 */
	public KeyPair generateKeyPair() throws GeneralSecurityException {
		// TOD generate a new RSA key pair (using BC as provider)
		// RSA_KEY_SPECS specifies the specs for the key....
		SecureRandom random = new SecureRandom();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
		generator.initialize(2048, random);
		
		return generator.generateKeyPair();
	}

	/**
	 * Regenerate an RSA public key from the private key.
	 */
	public PublicKey fromPrivateKey(PrivateKey privateKey) throws GeneralSecurityException {
		BigInteger exponent;
		BigInteger modulus;
		if (privateKey instanceof RSAPrivateKey) {
			// TOD Generate public key from RSA private key (see lecture)
			modulus = ((RSAPrivateKey) privateKey).getModulus();
			if (privateKey instanceof RSAPrivateCrtKey) {
				exponent = ((RSAPrivateCrtKey) privateKey).getPublicExponent();
			}else {
				exponent = RSA_KEY_SPECS.getPublicExponent();
			}
			
			RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(publicKeySpec);
		}
		throw new GeneralSecurityException("Trying to get the public key from a non-RSA private key.");
	}

	private SecureRandom random;

	public SecureRandom getRandom() throws GeneralSecurityException {
		if (random == null) {
			throw new GeneralSecurityException("Unable to find random algorithm SHA1PRNG.");
		}
		return random;
	}

	public byte[] getRandomBytes(int numBytes) throws GeneralSecurityException {
		byte[] salt = new byte[numBytes];
		getRandom().nextBytes(salt);
		return salt;
	}

	public long getRandomLong() throws GeneralSecurityException {
		return getRandom().nextLong();
	}

	
	private static void writeString(File f, String s) throws IOException {
		Writer wr = new BufferedWriter(FileUtils.openOutputCharFile(f));
		wr.append(s);
		wr.close();
	}
	
	private static String readString(File f) throws IOException {
		BufferedReader rd = new BufferedReader(FileUtils.openInputCharFile(f));
		StringBuilder sb = new StringBuilder();
		String line = rd.readLine();
		while (line != null) {
			sb.append(line);
			sb.append('\n');
			line = rd.readLine();
		}
		rd.close();
		return sb.toString();
	}
	
	/**
	 * Persist certificates and CSRs in PEM format to a string.
	 */
	public static String extern(Object cert) throws GeneralSecurityException {
		try {
			StringWriter sbuf = new StringWriter();
			JcaPEMWriter wr = new JcaPEMWriter(sbuf);
			wr.writeObject(cert);
			wr.flush();
			wr.close();
			String externCert = sbuf.toString();
			sbuf.close();
			return externCert;
		} catch (IOException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
	/**
	 * Persist certificates and CSRs in PEM format to a file.
	 */
	private static void extern(Object cert, File file) throws GeneralSecurityException {
		try {
			writeString(file, extern(cert));
		} catch (IOException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
	
	/**
	 * Write and read a certificate stored in external (PEM) format.
	 */
	public static String externCertificate(Certificate cert) throws GeneralSecurityException {
		return extern(cert);
	}
	
	public static void externCertificate(Certificate cert, File file) throws GeneralSecurityException {
		extern(cert, file);
	}

	public static Certificate internCertificate(InputStream in) throws GeneralSecurityException {
		try {
			CertificateFactory certFactory;
			certFactory = CertificateFactory.getInstance("X.509","BC");
			return certFactory.generateCertificate(in);
		} catch (CertificateException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (NoSuchProviderException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
	public static Certificate internCertificate(byte[] encoded) throws GeneralSecurityException {
		return internCertificate(new ByteArrayInputStream(encoded));
	}
	
	public static Certificate internCertificate(String encoded) throws GeneralSecurityException {
		try {
			return internCertificate(encoded.getBytes(StringUtils.CHARSET));
		} catch (UnsupportedEncodingException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
	public static Certificate internCertificate(File file) throws GeneralSecurityException, IOException {
		try {
			InputStream in = new BufferedInputStream(new FileInputStream(file));
			Certificate cert = internCertificate(in);
			in.close();
			return cert;
		} catch (IOException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
	/**
	 * Write and read a CSR stored in external (PEM) format.
	 */
	public static String externCSR(PKCS10CertificationRequest csr) throws GeneralSecurityException {
		return extern(csr);
	}

	public static void externCSR(PKCS10CertificationRequest csr, File file) throws GeneralSecurityException {
		extern(csr, file);
	}

	public static PKCS10CertificationRequest internCSR(String pem) throws GeneralSecurityException {
		try {
			ByteArrayInputStream pemStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
			Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
			PEMParser pemParser = new PEMParser(pemReader);

			Object parsedObj = pemParser.readObject();
			pemParser.close();

			if (parsedObj instanceof PKCS10CertificationRequest) {
				return (PKCS10CertificationRequest) parsedObj;
			} else {
				throw new GeneralSecurityException("Expected certification request: " + parsedObj);
			}
		} catch (UnsupportedEncodingException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (IOException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
	public static PKCS10CertificationRequest internCSR(File pemFile) throws GeneralSecurityException {
		try {
			return internCSR(readString(pemFile));
		} catch (IOException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
	


}
