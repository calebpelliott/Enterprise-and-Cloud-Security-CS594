package edu.stevens.cs594.chat.service.pki;

import java.io.File;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import edu.stevens.cs594.certgen.CertsService;
import edu.stevens.cs594.chat.service.ejb.IPkiService;
import edu.stevens.cs594.crypto.CAUtils;
import edu.stevens.cs594.crypto.PrivateCredential;
import edu.stevens.cs594.util.FileUtils;

/**
 * Injected into the PKI Web Service
 */
@RequestScoped
public class PkiService implements IPkiService {
	
	public static final String CHARSET = "UTF-8";
	
	public static final String ISSUER = "Stevens Institute of Technology";
	
	public static final String CA_ONLINE = CertsService.CA_ONLINE;
	
	public static final String CA_ONLINE_CERT_ALIAS = CertsService.CA_ONLINE_CERT_ALIAS;
	
	
	/**
	 * Keystore types.
	 */	
	// Online keystores and truststores
	private static final String APP_KEYSTORE_TYPE = CertsService.APP_KEYSTORE_TYPE;

	// private static final String APP_TRUSTSTORE_TYPE = CertsService.APP_TRUSTSTORE_TYPE;
	

	/**
	 * Files:
	 */	
	private static final String APP_KEYSTORE_FILENAME = "keystore.p12";
	
	// private static final String APP_TRUSTSTORE_FILENAME = "truststore.bks";
	
	private static final String PASSWORDS_FILENAME = "passwords.properties";
	
	// private static final String NAMES_FILENAME = "names.properties";
	
	/**
	 * Password properties
	 */
	public static final String APP_TRUSTSTORE_PASSWORD = CertsService.APP_TRUSTSTORE_PASSWORD;
	
	public static final String APP_KEYSTORE_PASSWORD = CertsService.APP_KEYSTORE_PASSWORD;
	
	public static final String APP_KEY_PASSWORD = CertsService.APP_KEY_PASSWORD;
	
	/**
	 * Property for absolute file path for domain.  BROKEN IN PAYARA 5.202!
	 */
	@SuppressWarnings("unused")
	private static final String DOMAIN_ROOT = "com.sun.aas.InstanceRoot";
	
	private static final String APP_SERVER_DIR = "PAYARA_DIR";
	
	private static final String DOMAIN_NAME = "DOMAIN_NAME";
		
	
	@Inject
	private CertsService certsService;
	
	private File keystoreAppFile;
		
	private char[] keystorePasswordApp;
	
	private char[] keyPasswordApp;
		
	private Logger logger = Logger.getLogger(PkiService.class.getCanonicalName());
	
	
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

			String password = properties.getProperty(APP_KEYSTORE_PASSWORD);
			if (password == null) {
				logger.severe("No online keystore password provided: " + APP_KEYSTORE_PASSWORD);
				return false;
			} else {
				keystorePasswordApp = password.toCharArray();
			}
			password = properties.getProperty(APP_KEY_PASSWORD);
			if (password == null) {
				logger.severe("No online key password provided: " + APP_KEY_PASSWORD);
				return false;
			} else {
				keyPasswordApp = password.toCharArray();
			}
		} catch (Exception e) {
			logger.log(Level.SEVERE, "Exception while reading passwords from " + passwordFile.getName(), e);
			return false;
		}
		return true;
	}
	
	/**
	 * Default constructor.
	 */
	public PkiService() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@PostConstruct
	private void init() {
		
		// Payara is giving /opt/payara for com.sun.aas.instanceRoot!
		// String domainRoot = System.getProperty(DOMAIN_ROOT);
		// logger.info("Deployed in domain directory: "+domainRoot);
		
		String appServerDir = System.getenv(APP_SERVER_DIR);
		String domainName = System.getenv(DOMAIN_NAME);
		String domainRoot = String.format("%s/glassfish/domains/%s", appServerDir, domainName);
		domainRoot = "C:\\Users\\caleb\\Documents\\git\\Enterprise-and-Cloud-Security-CS594\\hw2\\Assignment2-Code\\payara-5.2021.1\\payara5\\glassfish\\domains\\domain1";
		File configDir = new File(domainRoot, "config");
		
		keystoreAppFile = new File(configDir, APP_KEYSTORE_FILENAME);
		
		if (!keystoreAppFile.exists()) {
			throw new IllegalStateException("Keystore "+keystoreAppFile.getAbsolutePath()+" not found on server!");
		}
		
		File passwordsFile = new File(configDir, PASSWORDS_FILENAME);
		
		if (!passwordsFile.exists()) {
			throw new IllegalStateException("Passwords properties "+passwordsFile.getAbsolutePath()+" not found on server!");
		}
		
		loadPasswords(passwordsFile);
	}
	
	/**
	 * Generate a client cert from a CSR
	 */
	@Override
	public GenClientCertResponse genClientCert(String name, GenClientCertRequest request) throws GeneralSecurityException {

		String clientDns = request.getClientDns();
		
		// long duration = getDuration(options, CLIENT_CERT_DURATION);
		long duration = request.getDuration();

		long certId = certsService.getRandom().nextLong();
		
		PKCS10CertificationRequest csr = CertsService.internCSR(request.getCsr());
		
		String subjectName = CAUtils.getCN(csr.getSubject());
		
		if (!name.equals(subjectName)) {
			logger.info(String.format("Failed to issue client cert, requestor = %s, CSR CN = %s", name, subjectName));
			throw new GeneralSecurityException("Name mismatch between requestor and CN in CSR!");
		}
		
		KeyStore keystoreApp = certsService.load(keystoreAppFile, keystorePasswordApp, APP_KEYSTORE_TYPE);

		logger.info("Loading credential for "+CA_ONLINE_CERT_ALIAS+" from "+keystoreAppFile.getAbsolutePath());
		PrivateCredential ca = certsService.getCredential(keystoreApp, CA_ONLINE_CERT_ALIAS, keyPasswordApp);
	
		X509Certificate cert = null;
		
		logger.info("Signing credential for "+name);
		// TOD generate client cert from CSR using online CA key, write to certFile
		try {
			cert = CAUtils.createClientCert(certId, ca.getPrivateKey(), ca.getCertificate()[0], csr, clientDns, duration);
		} catch (CertIOException e) {
			// TOD Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TOD Auto-generated catch block
			e.printStackTrace();
		}
		
		GenClientCertResponse result = new GenClientCertResponse();
		result.setCert(CertsService.externCertificate(cert));
		return result;
		
	}


}