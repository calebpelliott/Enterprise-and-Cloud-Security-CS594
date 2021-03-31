package edu.stevens.cs594.certgen;

/*import java.io.BufferedInputStream;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.DecimalFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;*/
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.DecimalFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
/*import org.bouncycastle.asn1.eac.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;*/
//import edu.stevens.cs594.crypto.SecurityParams;

import edu.stevens.cs594.crypto.CAUtils;
import edu.stevens.cs594.crypto.PrivateCredential;
import edu.stevens.cs594.driver.Driver;
import edu.stevens.cs594.util.DateUtils;
import edu.stevens.cs594.util.ExceptionWrapper;
import edu.stevens.cs594.util.FileUtils;
import edu.stevens.cs594.util.Reporter;
import edu.stevens.cs594.util.StringUtils;



public class App implements Driver.Callback<App.Command,App.Option> {
	
	/**
	 * Invoke with arguments.
	 */
	
	private static final Logger logger = Logger.getLogger(App.class.getCanonicalName());

	private static final String PROMPT = "certs> ";
	
	/*
	 * Properties in the passwords file.
	 */
	private static final String OFFLINE_KEYSTORE_PASSWORD = "offline.keystore.password";
	private static final String OFFLINE_KEY_PASSWORD = "offline.key.password";
	@SuppressWarnings("unused")
	private static final String APP_TRUSTSTORE_PASSWORD = "app.truststore.password";
	private static final String APP_KEYSTORE_PASSWORD = "app.keystore.password";
	private static final String APP_KEY_PASSWORD = "app.key.password";
	
	private static final String AS_TRUSTSTORE_PASSWORD = "appserver.truststore.password";
	private static final String AS_KEYSTORE_PASSWORD = "appserver.keystore.password";
	private static final String AS_KEY_PASSWORD = "appserver.key.password";
	
	/*
	 * Properties in the distinguished names file.
	 */
	private static final String CA_ROOT = "ca.root";
	private static final String CA_ONLINE = "ca.online";
	private static final String SERVER_CERT = "server.cert";
	
	/*
	 * Distinguished names for certificates.
	 */
	private static X500Name caRoot;	
	private static X500Name caOnline;
	private static X500Name serverCert;
	
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
	private static final int ONE_YEAR = 365 * 24;
	
	private static final long CA_ROOT_DURATION = 10 * ONE_YEAR;
	
	private static final long CA_ONLINE_CERT_DURATION = 5 * ONE_YEAR;
		
	private static final long CLIENT_CERT_DURATION = ONE_YEAR;
	
	private static final long SERVER_CERT_DURATION = ONE_YEAR;
	
	/**
	 * Keystore types.
	 */
	// For root CA key.
	private static final String ROOT_KEYSTORE_TYPE = "PKCS12";
	
	// Online keystores and truststores
	private static final String APP_KEYSTORE_TYPE = "PKCS12";
	@SuppressWarnings("unused")
	private static final String APP_TRUSTSTORE_TYPE = "BKS";
	
	private static final String APP_SERVER_KEYSTORE_TYPE = "JKS";
	
	private static final String APP_SERVER_TRUSTSTORE_TYPE = "JKS";
	
	private static final String CLIENT_KEYSTORE_TYPE = "PKCS12";

	/**
	 * The certificate manager makes some assumptions about the organization of the space where keystores and
	 * truststores are managed.
	 * 
	 * Directories:
	 */	
	private static final String OFFLINE_DIR = "certs-offline";
	
	private static final String ONLINE_DIR = "certs-online";
	
	private static final String BACKUP_DIR = "certs-backup";
	
	private static final String BACKUP_OFFLINE_DIR = BACKUP_DIR + File.separatorChar + OFFLINE_DIR;
	
	private static final String BACKUP_ONLINE_DIR = BACKUP_DIR + File.separatorChar + ONLINE_DIR;
		
	/**
	 * Files:
	 */	
	private static final String ROOT_KEYSTORE_FILENAME = "caroot.p12";
	
	// private static final String ENCRYPTION_KEYSTORE_FILENAME = "keystore-encryption.p12";
	
	private static final String APP_KEYSTORE_FILENAME = "keystore.p12";
	
	@SuppressWarnings("unused")
	private static final String APP_TRUSTSTORE_FILENAME = "truststore.bks";
	
	private static final String APP_SERVER_KEYSTORE_FILENAME = "keystore.jks";
	
	private static final String APP_SERVER_TRUSTSTORE_FILENAME = "cacerts.jks";
	
	private static final String PASSWORDS_FILENAME = "passwords.properties";
	
	private static final String NAMES_FILENAME = "names.properties";
	
	private File keystoreRootFile;
	
	private File keystoreAppFile;
	
	private File keystoreAppServerFile;
	
	private File truststoreAppServerFile;
	
	private File baseDir;
	
	private Reporter reporter;
	
	private void initBasedir(File base, File namesFile) throws IOException {
		baseDir = base;
		FileUtils.ensureFolder(baseDir);
		
		File[] files = baseDir.listFiles();
		for (File file : files) {
			if (file.getName().equals(NAMES_FILENAME)) {
				return;
			}
		}
		Files.copy(namesFile.toPath(), Paths.get(baseDir.getName(), NAMES_FILENAME));
	}
	
	private void initFiles(File base, File passwordFile, File namesFile) throws IOException {
		initBasedir(base, namesFile);
		
		File offlineDir = new File(baseDir, OFFLINE_DIR);
		FileUtils.ensureFolder(offlineDir);
		File onlineDir = new File(baseDir, ONLINE_DIR);
		FileUtils.ensureFolder(onlineDir);
		
		File backupOfflineDir = new File(baseDir, BACKUP_OFFLINE_DIR);
		FileUtils.ensureFolder(backupOfflineDir);
		File backupAppDir = new File(baseDir, BACKUP_ONLINE_DIR);
		FileUtils.ensureFolder(backupAppDir);
		
		keystoreRootFile = new File(offlineDir, ROOT_KEYSTORE_FILENAME);
		keystoreAppFile = new File(onlineDir, APP_KEYSTORE_FILENAME);
		keystoreAppServerFile = new File(onlineDir, APP_SERVER_KEYSTORE_FILENAME);
		truststoreAppServerFile = new File(onlineDir, APP_SERVER_TRUSTSTORE_FILENAME);
		
		loadPasswords(passwordFile);

		loadNames(namesFile);
	}
	
	public static String backupFilename(String name) {
		String[] parts = name.split("\\.");
		String prefix = parts[0];
		String suffix = parts[1];
		
		Date date = new Date();
		GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(date);
		
		DecimalFormat twoDigitDecimalFormat = new DecimalFormat("00");
		DecimalFormat fourDigitDecimalFormat = new DecimalFormat("0000");
		
		String year = fourDigitDecimalFormat.format(calendar.get(Calendar.YEAR));
		String month = twoDigitDecimalFormat.format(calendar.get(Calendar.MONTH) + 1);
		String day = twoDigitDecimalFormat.format(calendar.get(Calendar.DAY_OF_MONTH));
		String hour = twoDigitDecimalFormat.format(calendar.get(Calendar.HOUR_OF_DAY));
		String minute = twoDigitDecimalFormat.format(calendar.get(Calendar.MINUTE));
		String second = twoDigitDecimalFormat.format(calendar.get(Calendar.SECOND));
		
		StringBuilder sb = new StringBuilder(prefix);
		
		sb.append(year)
		  .append("-")
		  .append(month)
		  .append("-")
		  .append(day)
		  .append("-")
		  .append(hour)
		  .append("-")
		  .append(minute)
		  .append("-")
		  .append(second)
		  .append('.')
		  .append(suffix);
		
		return sb.toString();
	}
	
	private void backup(Path file) throws IOException {
		if (Files.exists(file)) {
			String parentDir = file.getParent().getFileName().toString();
			String backupName = backupFilename(file.getFileName().toString());
			Files.copy(file, Paths.get(baseDir.getPath(), BACKUP_DIR, parentDir, backupName));
		}
	}
	
	/**
	 * Save the contents of the keystores after an update.
	 */
	public static void save(File store, char[] password, String keystoreType, KeyStore keystore) throws GeneralSecurityException {
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
	
	private void updateKeystore(File keystoreFile, KeyStore keystore, String keystoreType, char[] password) throws GeneralSecurityException, IOException {
		backup(keystoreFile.toPath());
		save(keystoreFile, password, keystoreType, keystore);
	}

	/**
	 * Load an individual keystore (from CredentialManager).
	 */
	public static KeyStore load(File store, char[] password, String keystoreType) throws GeneralSecurityException {
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

	private static X509Certificate[] toX509Certificates(Certificate[] certificates) {
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
	public static PrivateCredential getCredential(KeyStore keystore, String alias, char[] password) throws GeneralSecurityException {
		PrivateKey key = (PrivateKey) keystore.getKey(alias, password);
		X509Certificate[] chain = toX509Certificates(keystore.getCertificateChain(alias));
		
		// TODO get key and cert chain from the keystore
		
		return new PrivateCredential(chain, key, alias);
	}
	
	/**
	 * Retrieve a certificate from a truststore.
	 */
	public static X509Certificate getCertificate(KeyStore truststore, String alias) throws GeneralSecurityException {
		Certificate certificate = truststore.getCertificate(alias);
		
		// TODO get certificate from the truststore
		
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
	public static KeyPair generateKeyPair() throws GeneralSecurityException {
		SecureRandom random = new SecureRandom();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
		generator.initialize(2048, random);
		//RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();
		//RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
		//PrivateKey priv = kp.getPrivate();
		//priv.
		//PublicKey pub = fromPrivateKey((PrivateKey) priv);
		
		//public RSAKeyGenParameterSpec RSA_KEY_SPECS = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
		/*RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
				new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
				new BigInteger("57791d5430d593164082036ad8b29fb1", 16));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");*/
		//RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
		//PublicKey pub = fromPrivateKey(privKey);
		return generator.generateKeyPair();
	}

	/**
	 * Regenerate an RSA public key from the private key.
	 */
	public static PublicKey fromPrivateKey(PrivateKey privateKey) throws GeneralSecurityException {
		BigInteger exponent;
		BigInteger modulus;
		if (privateKey instanceof RSAPrivateKey) {
			// TODO Generate public key from RSA private key (see lecture)
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

	static SecureRandom random;

	static {
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			logger.log(Level.SEVERE, "Unable to find random algorithm SHA1PRNG.", e);
		}
	}

	public static SecureRandom getRandom() throws GeneralSecurityException {
		if (random == null) {
			throw new GeneralSecurityException("Unable to find random algorithm SHA1PRNG.");
		}
		return random;
	}

	public static byte[] getRandomBytes(int numBytes) throws GeneralSecurityException {
		byte[] salt = new byte[numBytes];
		getRandom().nextBytes(salt);
		return salt;
	}

	public static long getRandomLong() throws GeneralSecurityException {
		return getRandom().nextLong();
	}

	
	private char[] keystorePasswordOffline;
	
	private char[] keyPasswordOffline;
	
	// private char[] appTruststorePassword;
	
	private char[] keystorePasswordApp;
	
	private char[] keyPasswordApp;
	
	private char[] truststorePasswordAppServer;
	
	private char[] keystorePasswordAppServer;
	
	private char[] keyPasswordAppServer;
	
	/**
	 * Load passwords for key stores, keys and truststores
	 * @param passwordFile
	 * @return
	 */
	private boolean loadPasswords(File passwordFile) {
		try {
			Properties properties = new Properties();
			Reader in = FileUtils.openInputCharFile(passwordFile);
			properties.load(in);
			in.close();

			String password = properties.getProperty(OFFLINE_KEYSTORE_PASSWORD);
			if (password == null) {
				say("No offline keystore password provided: " + OFFLINE_KEYSTORE_PASSWORD);
				return false;
			} else {
				keystorePasswordOffline = password.toCharArray();
			}
			password = properties.getProperty(OFFLINE_KEY_PASSWORD);
			if (password == null) {
				say("No offline key password provided: " + OFFLINE_KEY_PASSWORD);
				return false;
			} else {
				keyPasswordOffline = password.toCharArray();
			}
			password = properties.getProperty(APP_KEYSTORE_PASSWORD);
			if (password == null) {
				say("No online keystore password provided: " + APP_KEYSTORE_PASSWORD);
				return false;
			} else {
				keystorePasswordApp = password.toCharArray();
			}
			password = properties.getProperty(APP_KEY_PASSWORD);
			if (password == null) {
				say("No online key password provided: " + APP_KEY_PASSWORD);
				return false;
			} else {
				keyPasswordApp = password.toCharArray();
			}
			password = properties.getProperty(AS_TRUSTSTORE_PASSWORD);
			if (password == null) {
				say("No app server truststore password provided: " + AS_TRUSTSTORE_PASSWORD);
				return false;
			} else {
				truststorePasswordAppServer = password.toCharArray();
			}
			password = properties.getProperty(AS_KEYSTORE_PASSWORD);
			if (password == null) {
				say("No app server keystore password provided: " + AS_KEYSTORE_PASSWORD);
				return false;
			} else {
				keystorePasswordAppServer = password.toCharArray();
			}
			password = properties.getProperty(AS_KEY_PASSWORD);
			if (password == null) {
				say("No key password provided: " + AS_KEY_PASSWORD);
				return false;
			} else {
				keyPasswordAppServer = password.toCharArray();
			}
		} catch (Exception e) {
			reporter.error("Exception while reading passwords from " + passwordFile.getName(), e);
			return false;
		}
		return true;
	}
	
	/**
	 * Load distinguished names for X509 certs
	 * @param namesFile
	 * @return
	 */
	private boolean loadNames(File namesFile) {
		try {
			Properties properties = new Properties();
			Reader in = FileUtils.openInputCharFile(namesFile);
			properties.load(in);
			in.close();
			String name = properties.getProperty(CA_ROOT);
			if (name == null) {
				say("Missing distinguished name: " + CA_ROOT);
				return false;
			} else {
				caRoot = new X500Name(name);
			}
			name = properties.getProperty(SERVER_CERT);
			if (name == null) {
				say("Missing distinguished name: " + SERVER_CERT);
				return false;
			} else {
				serverCert = new X500Name(name);
			}
			name = properties.getProperty(CA_ONLINE);
			if (name == null) {
				say("Missing distinguished name: " + CA_ONLINE);
				return false;
			} else {
				caOnline = new X500Name(name);
			}
		} catch (Exception e) {
			logger.log(Level.SEVERE, "Exception while reading names from " + namesFile.getName(), e);
			return false;
		}
		return true;
	}

	/**
	 * Command line arguments (options and option arguments)
	 */
	public static enum Command {
		
		/*
		 * Admin commands
		 */
		HELP("help"),
		SHOW_CERTIFICATES("showcerts"),
		/*
		 * Commands for offline keystore
		 */
		GENERATE_CA_ROOT("gencaroot"),
		EXPORT_CA_ROOT_CERT("exportcaroot"),
		/*
		 * Commands for online server keystores
		 */
		GENERATE_SERVER_SSL_CERT("genservercert"),
		GENERATE_CA_ONLINE_CERT("genonlinecacert"),
		EXPORT_CA_ONLINE_CERT("exportonlinecacert"),
		/*
		 * Commands for online client (will be moved to the server)
		 */
		GENERATE_CLIENT_CERT("genclientcert"),
		GENERATE_CLIENT_ROOT("genclientroot"),
		GENERATE_CSR("genclientcsr"),
		IMPORT_CLIENT_CERT("importclientcert");
		
		private String value;
		private Command(String v) {
			value = v;
		}
		public String value() {
			return value;
		}
	}
	
	public static enum Option {
		/*
		 * Command-line options:
		 */
		BASE_DIR("basedir"),
		PASSWORD_FILE("passwordfile"),
		NAMES_FILE("namesfile"),
		SCRIPT_FILE("scriptfile"),
		/*
		 * Arguments:
		 */
		CERT_FILE("cert"),
		DNS_NAME("dns"),
		DURATION("duration"),
		CLIENT_DN("dn"),
		CLIENT_CSR_FILE("csr"),
		CLIENT_KEY_STORE("keystore"),
		CLIENT_STORE_PASSWORD("storepass"),
		CLIENT_KEY_PASSWORD("keypass");
		
		private String value;
		private boolean param;
		private Option(String v) {
			value = v;
			param = true;
		}
		public String value() {
			return value;
		}
		public boolean isParam() {
			return param;
		}
	}
	
	private void say(String msg, Command arg) {
		reporter.say(String.format(msg, arg.value()));
	}

	private void say(String msg, Option arg) {
		reporter.say(String.format(msg, arg.value()));
	}

	private void say(String msg) {
		reporter.say(msg);
	}

	private void flush() {
		reporter.flush();
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
	
	private void execute(Driver<Command,Option> driver, String[] args) throws Exception {
		Map<Option,String> options = new HashMap<Option,String>();
		driver.parseOptions(args, options);
		initialize(options);
		
		if (options.containsKey(Option.SCRIPT_FILE)) {
			String scriptName = options.get(Option.SCRIPT_FILE);
			BufferedReader rd = new BufferedReader(new InputStreamReader(new FileInputStream(scriptName), StringUtils.CHARSET));
			driver.batch(rd);
		} else {
			driver.interactive(PROMPT);
		}
	}
	
	@Override
	public void execute(Command command, Map<Option, String> options) throws Exception {
		if (command == null) {
			displayHelp();
			return;
		}
		switch (command) {
		case HELP:
			displayHelp();
			break;
		case SHOW_CERTIFICATES:
			showCerts(options);
			break;
		case GENERATE_CA_ROOT:
			genCaRoot(options);
			break;
		case EXPORT_CA_ROOT_CERT:
			exportCaRootCert(options);
			break;
		case GENERATE_SERVER_SSL_CERT:
			genServerCert(options);
			break;
		case GENERATE_CA_ONLINE_CERT:
			genOnlineCaCert(options);
			break;
		case EXPORT_CA_ONLINE_CERT:
			exportOnlineCaCert(options);
			break;
		case GENERATE_CLIENT_CERT:
			genClientCert(options);
			break;
		/*
		 * These should be client-side operations.  We include them in the cert manager
		 * for the sake of the assignment.
		 */
		case GENERATE_CLIENT_ROOT:
			genClientRoot(options);
			break;
		case GENERATE_CSR:
			genClientCSR(options);
			break;
		case IMPORT_CLIENT_CERT:
			importClientCert(options);
			break;
		default:
			throw new IllegalArgumentException("Unrecognized command: " + command.name());
		}
	}
	
	public void displayHelp() {
		say("");
		say("Commands for offline keystore:");
		say("  %s: Generate CA root certificate.", Command.GENERATE_CA_ROOT);
		say("  %s: Export root CA certificate (for inclusion in client truststore).", Command.EXPORT_CA_ROOT_CERT);
		say("");
		say("Commands for online keystore:");
		say("  %s: Generate server SSL certificate.", Command.GENERATE_SERVER_SSL_CERT);
		say("  %s: Generate CA certificate for signing client certificates.", Command.GENERATE_CA_ONLINE_CERT);
		say("  %s: Export online CA certificate.", Command.EXPORT_CA_ONLINE_CERT);
		say("  %s: Generate client certificate from input CSR.", Command.GENERATE_CLIENT_CERT);
		say("");
		say("Commands for client keystore:");
		say("  %s: Initialize client keystore with self-signed cert.", Command.GENERATE_CLIENT_ROOT);
		say("  %s: Generate CSR from client cert.", Command.GENERATE_CSR);
		say("  %s: Import client cert from PEM file.", Command.IMPORT_CLIENT_CERT);
		say("");
		say("Global commands:");
		say("  %s: Display metadata about certificates.", Command.SHOW_CERTIFICATES);
		say("");
		say("Command options:");
		say("--%s: Certificate file (PEM format).", Option.CERT_FILE);
		say("--%s: DNS for client or server cert.", Option.DNS_NAME);
		say("--%s: Duration of certificates (in years).", Option.DURATION);
		say("--%s: Client distinguished name.", Option.CLIENT_DN);
		say("--%s: Client CSR file (PEM format).", Option.CLIENT_CSR_FILE);
		say("--%s: Client keystore.", Option.CLIENT_KEY_STORE);
		say("--%s: Client keystore password.", Option.CLIENT_STORE_PASSWORD);
		say("--%s: Client credential password (client keystore).", Option.CLIENT_KEY_PASSWORD);
		say("");
		say("Command-line options:");
		say("--%s: Base directory for certificate management.", Option.BASE_DIR);
		say("--%s: Properties file with keystore passwords.", Option.PASSWORD_FILE);
		say("--%s: Properties file with distinguished names for certificates.", Option.NAMES_FILE);
		say("--%s: Name of a file containing a script to execute.", Option.SCRIPT_FILE);
		say("");
		flush();
	}
	
	private long getDuration(Map<Option, String> options, long defaultDuration) {
		String duration = options.get(Option.DURATION);
		if (duration == null) {
			return defaultDuration;
		}
		return Long.parseLong(duration);
	}
	
	/**
	 * Generate root CA for server CA for server SSL, stored in the offline keystore.
	 */
	private void genCaRoot(Map<Option,String> options) throws Exception {
		if (keystoreRootFile.exists()) {
			throw new IllegalStateException("Attempting to regenerate the CA root certificate.");
		}
		
		long duration = getDuration(options, CA_ROOT_DURATION);
		
		KeyStore keystoreRoot = load(keystoreRootFile, keystorePasswordOffline, ROOT_KEYSTORE_TYPE);
		
		KeyPair kp = generateKeyPair();
		
		long certId = getRandom().nextLong();
		
		X509Certificate cert = null;
		
		// TODO generate root CA cert (see CAUtils)
		cert = CAUtils.createCaRootCert(certId, caRoot, kp, duration);
		
		Certificate[] chain = new Certificate[]{cert};
		
		keystoreRoot.setKeyEntry(CA_ROOT_ALIAS, kp.getPrivate(), keyPasswordOffline, chain);
		
		updateKeystore(keystoreRootFile, keystoreRoot, ROOT_KEYSTORE_TYPE, keystorePasswordOffline);
	}
	
	private File getCertFile(Map<Option,String> options) throws IOException {
		String f = options.get(Option.CERT_FILE);
		if (f == null) {
			throw new IOException("Required: name of certificate file.");
		}
		return new File(baseDir, f);
	}
	
	/**
	 * Persist certificates and CSRs in PEM format to a string.
	 */
	private static String extern(Object cert) throws GeneralSecurityException {
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
	
	/**
	 * Export CA root cert as a PEM file.
	 */
	private void exportCaRootCert(Map<Option,String> options) throws Exception {
		File certFile = getCertFile(options);
		
		// TODO write CA root cert to a PEM file: load the root keystore, get the root CA private credential, 
		// convert to string (see externCertificate), then write that to the certFile
		KeyStore keystoreRoot = load(keystoreRootFile, keystorePasswordOffline, ROOT_KEYSTORE_TYPE);
		Certificate cert = keystoreRoot.getCertificate(CA_ROOT_ALIAS);
		externCertificate(cert, certFile);
	}
	
	/**
	 * Generate key pair for server CA for server SSL, stored in the app server keystore.
	 */
	private void genServerCert(Map<Option,String> options) throws Exception {
		String serverDNS = options.get(Option.DNS_NAME);
		if (serverDNS == null) {
			reporter.error("Missing server DNS.");
			return;
		}
		long duration = getDuration(options, SERVER_CERT_DURATION);
		
		KeyStore keystoreRoot = load(keystoreRootFile, keystorePasswordOffline, ROOT_KEYSTORE_TYPE);

		PrivateCredential root = getCredential(keystoreRoot, CA_ROOT_ALIAS, keyPasswordOffline);
	
		KeyPair kp = generateKeyPair();
		
		long certId = getRandom().nextLong();
		
		X509Certificate cert = null;
		
		// TODO create server cert and cert chain
		cert = CAUtils.createServerCert(certId, root.getPrivateKey(), root.getCertificate()[0], serverCert, serverDNS, kp.getPublic(), duration);
		
		Certificate[] chain = new Certificate[]{cert, root.getCertificate()[0]};
		/*
		 * TODO Save credential in the app server keystore (use load and updateKeystore)
		 */
		KeyStore serverKeyStore = load(keystoreAppServerFile, keystorePasswordAppServer, APP_SERVER_KEYSTORE_TYPE);
		serverKeyStore.setKeyEntry(SERVER_CERT_ALIAS, kp.getPrivate(), keystorePasswordAppServer, chain);
		updateKeystore(keystoreAppServerFile, serverKeyStore, APP_SERVER_KEYSTORE_TYPE, keystorePasswordAppServer);
		/*
		 * TODO Save certificate in the app server truststore.
		 */
		KeyStore serverTrustStore = load(truststoreAppServerFile, truststorePasswordAppServer, APP_SERVER_TRUSTSTORE_TYPE);
		serverTrustStore.setCertificateEntry(SERVER_CERT_ALIAS, cert);
		updateKeystore(truststoreAppServerFile, serverTrustStore, APP_SERVER_TRUSTSTORE_TYPE, truststorePasswordAppServer);

	}

	/**
	 * Generate private key for online CA for client certs, stored in the app keystore.
	 */
	private void genOnlineCaCert(Map<Option,String> options) throws Exception {
		long duration = getDuration(options, CA_ONLINE_CERT_DURATION);
		
		KeyStore keystoreOffline = load(keystoreRootFile, keystorePasswordOffline, ROOT_KEYSTORE_TYPE);

		PrivateCredential root = getCredential(keystoreOffline, CA_ROOT_ALIAS, keyPasswordOffline);
	
		KeyPair kp = generateKeyPair();
		
		long certId = getRandom().nextLong();
		
		X509Certificate cert = null;
		
		// TODO create online CA cert
		cert = CAUtils.createOnlineCaCert(certId, root.getPrivateKey(), root.getCertificate()[0], caOnline, kp.getPublic(), duration);

		Certificate[] chain = new Certificate[]{cert, root.getCertificate()[0]};
		
		/*
		 * TODO Save the credentials in the online keystore (use load and updateKeystore)
		 */
		KeyStore caKeyStore = load(keystoreAppFile, keystorePasswordApp, APP_KEYSTORE_TYPE);
		caKeyStore.setKeyEntry(CA_ONLINE_CERT_ALIAS, kp.getPrivate(), keystorePasswordApp, chain);
		updateKeystore(keystoreAppFile, caKeyStore, APP_KEYSTORE_TYPE, keystorePasswordApp);
		
		/*
		 * TODO Save the intermediate certificate in the app server truststore (for client authentication).
		 */
		KeyStore serverTrustStore = load(truststoreAppServerFile, truststorePasswordAppServer, APP_SERVER_TRUSTSTORE_TYPE);
		serverTrustStore.setCertificateEntry(CA_ONLINE_CERT_ALIAS, cert);
		updateKeystore(truststoreAppServerFile, serverTrustStore, APP_SERVER_TRUSTSTORE_TYPE, truststorePasswordAppServer);
	}
	
	/**
	 * Export online CA cert as a PEM file.
	 */
	private void exportOnlineCaCert(Map<Option,String> options) throws Exception {
		File certFile = getCertFile(options);
		PrivateCredential cred = null;
		
		// TODO get online CA cert from app keystore and extract credential
		KeyStore keystoreOnline = load(keystoreAppFile, keystorePasswordApp, APP_KEYSTORE_TYPE);
		cred = getCredential(keystoreOnline, CA_ONLINE_CERT_ALIAS, keystorePasswordApp);
		
		writeString(certFile, externCertificate(cred.getCertificate()[0]));
	}
	
	/**
	 * Generate a client cert from a CSR
	 */
	private void genClientCert(Map<Option,String> options) throws Exception {
		String clientCsrFile = options.get(Option.CLIENT_CSR_FILE);
		if (clientCsrFile == null) {
			reporter.error("Missing file name for client CSR.");
			return;
		}
		String certFile = options.get(Option.CERT_FILE);
		if (certFile == null) {
			reporter.error("Missing file name for client certificate.");
			return;
		}
		String clientDns = options.get(Option.DNS_NAME);
		
		long duration = getDuration(options, CLIENT_CERT_DURATION);

		long certId = getRandom().nextLong();
		
		PKCS10CertificationRequest request = internCSR(new File(clientCsrFile));
		
		KeyStore keystoreApp = load(keystoreAppFile, keystorePasswordApp, APP_KEYSTORE_TYPE);

		PrivateCredential ca = getCredential(keystoreApp, CA_ONLINE_CERT_ALIAS, keyPasswordApp);
	
		X509Certificate cert = null;
		
		// TODO generate client cert from CSR using online CA key, write to certFile
		cert = CAUtils.createClientCert(certId, ca.getPrivateKey(), ca.getCertificate()[0], request, clientDns, duration);
		externCertificate(cert, new File(certFile));
	}
	
	/*
	 * The following operations belong on the client side.  We put them here for the assignment.
	 */
	
	/**
	 * Generate initial v1 self-signed cert for a client.
	 */
	private void genClientRoot(Map<Option,String> options) throws Exception {
		String clientName = options.get(Option.CLIENT_DN);
		if (clientName == null) {
			reporter.error("Missing client distinguished name.");
			return;
		}
		String clientKeystoreFilename = options.get(Option.CLIENT_KEY_STORE);
		if (clientKeystoreFilename == null) {
			reporter.error("Missing client key store.");
			return;
		}
		File clientKeystoreFile = new File(clientKeystoreFilename);
		String duration = options.get(Option.DURATION);
		if (duration == null) {
			reporter.error("Must specify a duration for a client certificate.");
		}
		String clientKeystorePassword = options.get(Option.CLIENT_STORE_PASSWORD);
		if (clientKeystorePassword == null) {
			reporter.error("Missing client key store password.");
			return;
		}
		String clientKeyPassword = options.get(Option.CLIENT_KEY_PASSWORD);
		if (clientKeyPassword == null) {
			reporter.error("Missing client key password.");
			return;
		}
		
		long id = getRandomLong();
		X500Name clientDn = new X500Name(clientName);
		KeyPair keyPair = generateKeyPair();
		
		// Create self-signed v1 cert and save in client keystore
		X509Certificate cert = CAUtils.createClientRootCert(id, clientDn, keyPair, Long.parseLong(duration));
		X509Certificate[] chain = { cert };
		KeyStore clientStore = load(clientKeystoreFile, clientKeystorePassword.toCharArray(), CLIENT_KEYSTORE_TYPE);
		clientStore.setKeyEntry(CLIENT_CERT_ALIAS, keyPair.getPrivate(), clientKeyPassword.toCharArray(), chain);
		save(clientKeystoreFile, clientKeystorePassword.toCharArray(), clientKeyPassword, clientStore);
	}

	/**
	 * Generate client CSR signed by their private key
	 */
	private void genClientCSR(Map<Option,String> options) throws Exception {
		String clientKeystoreFilename = options.get(Option.CLIENT_KEY_STORE);
		if (clientKeystoreFilename == null) {
			reporter.error("Missing client key store.");
			return;
		}
		File clientKeystoreFile = new File(clientKeystoreFilename);
		String clientKeystorePassword = options.get(Option.CLIENT_STORE_PASSWORD);
		if (clientKeystorePassword == null) {
			reporter.error("Missing client key store password.");
			return;
		}
		String clientKeyPassword = options.get(Option.CLIENT_KEY_PASSWORD);
		if (clientKeyPassword == null) {
			reporter.error("Missing client key password.");
			return;
		}
		String clientCsrFile = options.get(Option.CLIENT_CSR_FILE);
		if (clientCsrFile == null) {
			reporter.error("Missing file name for client CSR.");
			return;
		}
		
		// May be null
		String clientDns = options.get(Option.DNS_NAME);
		
		KeyStore clientStore = load(clientKeystoreFile, clientKeystorePassword.toCharArray(), CLIENT_KEYSTORE_TYPE);
		try {
			PKCS10CertificationRequest csr = null;
			
			PrivateCredential pc = getCredential(clientStore, CLIENT_CERT_ALIAS, clientKeyPassword.toCharArray());
			KeyPair kp = new KeyPair(fromPrivateKey(pc.getPrivateKey()), pc.getPrivateKey());
			X500Name clientDn = CAUtils.toX500Name(pc.getCertificate()[0].getSubjectX500Principal());

			// TODO generate a CSR signed by the client's private key
			csr = CAUtils.createCSR(clientDn, kp, clientDns);
			
			extern(csr, new File(clientCsrFile));
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
	private void importClientCert(Map<Option,String> options) throws Exception {
		String clientKeystoreFilename = options.get(Option.CLIENT_KEY_STORE);
		if (clientKeystoreFilename == null) {
			reporter.error("Missing client key store.");
			return;
		}
		File clientKeystoreFile = new File(clientKeystoreFilename);
		String clientKeystorePassword = options.get(Option.CLIENT_STORE_PASSWORD);
		if (clientKeystorePassword == null) {
			reporter.error("Missing client key store password.");
			return;
		}
		String clientKeyPassword = options.get(Option.CLIENT_KEY_PASSWORD);
		if (clientKeyPassword == null) {
			reporter.error("Missing client key password.");
			return;
		}
		String clientCertFile = options.get(Option.CERT_FILE);
		if (clientCertFile == null) {
			reporter.error("Missing file name for client CSR.");
			return;
		}
		
		KeyStore clientStore = load(clientKeystoreFile, clientKeystorePassword.toCharArray(), CLIENT_KEYSTORE_TYPE);

		// TODO import the cert from clientCertFile and store it in the clientstore
		Certificate clientCert = internCertificate(new File(clientCertFile));
		//Certificate clientCert = load(clientFile, clientKeyPassword.toCharArray(), CLIENT_KEYSTORE_TYPE).getCertificate(CA_ONLINE_CERT_ALIAS);
		PrivateCredential pc = getCredential(clientStore, CLIENT_CERT_ALIAS, clientKeyPassword.toCharArray());
		X509Certificate[] chain =  {((X509Certificate) clientCert)};
		//clientStore.setKeyEntry(CLIENT_CERT_ALIAS, );
		clientStore.setKeyEntry(CLIENT_CERT_ALIAS, pc.getPrivateKey(), clientKeyPassword.toCharArray(), chain);
		//Enumeration<String> s = clientStore.aliases();
		//clientStore.setCertificateEntry(CLIENT_CERT_ALIAS, clientCert);
		updateKeystore(clientKeystoreFile, clientStore, CLIENT_KEYSTORE_TYPE, clientKeyPassword.toCharArray());
	}
	
	/**
	 * Display information about all private keys.
	 */
	private void showCerts(Map<Option, String> options) throws Exception {
		if (keystoreRootFile.exists()) {
			KeyStore keystoreRoot = load(keystoreRootFile, keystorePasswordOffline, ROOT_KEYSTORE_TYPE);
			PrivateCredential root = getCredential(keystoreRoot, CA_ROOT_ALIAS, keyPasswordOffline);
			showCredentialInfo("CA Root:", root);
		}

		if (keystoreAppFile.exists()) {
			KeyStore keystoreApp = load(keystoreAppFile, keystorePasswordApp, APP_KEYSTORE_TYPE);
			PrivateCredential onlineCa = getCredential(keystoreApp, CA_ONLINE_CERT_ALIAS, keyPasswordApp);
			showCredentialInfo("CA Online:", onlineCa);
		}

		if (keystoreAppServerFile.exists()) {
			KeyStore keystoreApp = load(keystoreAppServerFile, keystorePasswordAppServer, APP_SERVER_KEYSTORE_TYPE);
			PrivateCredential serverSSL = getCredential(keystoreApp, SERVER_CERT_ALIAS, keyPasswordAppServer);
			showCredentialInfo("Server:", serverSSL);
		}
		
		String clientKeystoreFilename = options.get(Option.CLIENT_KEY_STORE);
		if (clientKeystoreFilename == null) {
			return;
		}
		String clientKeystorePassword = options.get(Option.CLIENT_STORE_PASSWORD);
		if (clientKeystorePassword == null) {
			reporter.error("Missing client key store password.");
			return;
		}
		String clientKeyPassword = options.get(Option.CLIENT_KEY_PASSWORD);
		if (clientKeyPassword == null) {
			reporter.error("Missing client key password.");
			return;
		}
		File clientKeystoreFile = new File(clientKeystoreFilename);
		if (clientKeystoreFile.exists()) {
			KeyStore clientStore = load(clientKeystoreFile, clientKeystorePassword.toCharArray(), CLIENT_KEYSTORE_TYPE);
			PrivateCredential clientCert = getCredential(clientStore, CLIENT_CERT_ALIAS, clientKeyPassword.toCharArray());
			showCredentialInfo("Client:", clientCert);
		} else {
			reporter.error("No such client keystore: "+clientKeystoreFilename);
		}
		

	}
	
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
		byte[] fp = getFingerprint(fromPrivateKey(credential.getPrivateKey()).getEncoded());
		say("SHA1: " + displayHex(fp));
		for (X509Certificate certificate : credential.getCertificate()) {
			say("--------------------------------------------------------------------------------");
			showCertificateInfo(certificate);
		}
		say("");
	}
	
	@SuppressWarnings("unused")
	private void showCertificateInfo(String certName, X509Certificate certificate) throws GeneralSecurityException {
		say("================================================================================");
		say(certName);
		byte[] fp = getFingerprint(certificate.getPublicKey().getEncoded());
		say("SHA1: " + displayHex(fp));
		say("--------------------------------------------------------------------------------");
		showCertificateInfo(certificate);
		say("");
	}
	
	private void showCertificateInfo(X509Certificate certificate) throws GeneralSecurityException {
		say(String.format("Issuer: %s", certificate.getIssuerDN().toString()));
		say(String.format("Subject: %s", certificate.getSubjectDN().toString()));
		say("Serial number: "+certificate.getSerialNumber().toString(16));
		say("SHA1: " + displayHex(getCertFingerprint(certificate)));
		Date before = certificate.getNotBefore();
		Date after = certificate.getNotAfter();
		say(String.format("Valid from %s to %s", DateUtils.dateTimeFormat(before), DateUtils.dateTimeFormat(after)));
	}
	
	
	public static void main(String[] args) {
		
		Reporter reporter = Reporter.createReporter();
		
		App app = new App(reporter, args);
		
		Driver<Command,Option> driver = new Driver<Command,Option>(reporter, app);
		
		try {
			app.execute(driver, args);
		} catch (Exception e) {
			// reporter.error(e.getMessage(), e);
			logger.log(Level.SEVERE, "Uncaught exception.", e);
		}

	}

	private Map<String,Command> commands;

	private Map<String,Option> options;
	
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	public App(Reporter reporter, String[] args) {
		this.reporter = reporter;

		commands = new HashMap<String, Command>();
		for (Command command : Command.values()) {
			commands.put(command.value(), command);
		}
				
		options = new HashMap<String, Option>();
		for (Option option : Option.values()) {
			options.put(option.value(), option);
		}
		
	}
	
	@Override
	public Command lookupCommand(String arg) {
		return commands.get(arg);
	}

	@Override
	public Option lookupOption(String arg) {
		return options.get(arg);
	}

	@Override
	public boolean isParameterized(Option option) {
		return option.isParam();
	}
	
	private void initialize(Map<Option,String> options) throws IOException {
		File passwordsFile;
		File namesFile;
		
		String baseDir = options.get(Option.BASE_DIR);
		if (baseDir == null) {
			baseDir = Paths.get("").toAbsolutePath().toString();
		}
		File baseDirFile = new File(baseDir);
		
		String passwords = options.get(Option.PASSWORD_FILE);
		if (passwords != null) {
			passwordsFile = new File(passwords);
		} else {
			passwordsFile = new File(baseDirFile, PASSWORDS_FILENAME);
		}
		
		String names = options.get(Option.NAMES_FILE);
		if (names != null) {
			namesFile = new File(names);
		} else {
			namesFile = new File(baseDirFile, NAMES_FILENAME);
		}
		
		initFiles(baseDirFile, passwordsFile, namesFile);
	}

}
