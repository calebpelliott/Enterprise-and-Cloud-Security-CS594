package edu.stevens.cs594.chat.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.weld.environment.se.Weld;
import org.jboss.weld.environment.se.WeldContainer;

import edu.stevens.cs594.certgen.CertsService;
import edu.stevens.cs594.chat.service.ejb.IPkiService.GenClientCertRequest;
import edu.stevens.cs594.chat.service.ejb.IPkiService.GenClientCertResponse;
import edu.stevens.cs594.driver.Driver;
import edu.stevens.cs594.util.Reporter;
import edu.stevens.cs594.util.StringUtils;

public class App implements Driver.Callback<App.Command,App.Option> {
	
	/**
	 * Invoke with arguments.
	 */
	
	private static final Logger logger = Logger.getLogger(App.class.getCanonicalName());

	private static final String PROMPT = "client> ";
	
	/**
	 * Files:
	 */		
	private static final String CLIENT_KEYSTORE_FILENAME = "clientKeystore.jks";
	
	private static final String CLIENT_TRUSTSTORE_FILENAME = "clientTruststore.jks";

	private static final String PASSWORDS_FILENAME = "passwords.properties";
	
	
	private ClientCerts clientCerts;
	
	private Reporter reporter;

	private Map<String,Command> commands;

	private Map<String,Option> options;
	
	
	/**
	 * Command line arguments (options and option arguments)
	 */
	public static enum Command {
		
		/*
		 * Admin commands
		 */
		HELP("help"),
		IMPORT("import"),
		INIT("init"),
		REGISTER("register"),
		SHOW("show"),
		POST("post");
		
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
		KEYSTORE("keystore"),
		TRUSTSTORE("truststore"),
		PASSWORD_FILE("passwordfile"),
		CA_URI("caUri"),
		SERVER_URI("serverUri"),
		SENDER_NAME("sender"),
		SENDER_PASSWORD("password"),
		SENDER_DN("dn"),
		SCRIPT_FILE("scriptfile"),
		/*
		 * Arguments:
		 */
		CERT_FILE("cert"),
		DNS_NAME("dns"),
		DURATION("duration"),
		CLIENT_CSR_FILE("csr"),
		CLIENT_KEY_STORE("keystore"),
		CLIENT_STORE_PASSWORD("storepass"),
		CLIENT_KEY_PASSWORD("keypass");
		
		private String value;
		private boolean param;
		private Option(String v, boolean p) {
			value = v;
			param = p;
		}
		private Option(String v) {
			this(v,true);
		}
		public String value() {
			return value;
		}
		public boolean isParam() {
			return param;
		}
	}
	
	private static final long CLIENT_CERT_DURATION = CertsService.CLIENT_CERT_DURATION;

	
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
	
	private Reporter getReporter() {
		return reporter;
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
	public void execute(Command command, Map<Option,String> options) throws Exception {
		if (command == null) {
			displayHelp();
			return;
		}
		switch (command) {
		case HELP:
			displayHelp();
			break;
		case INIT:
			initKeystore(options);
			break;
		case IMPORT:
			initTruststore(options);
			break;
		case REGISTER:
			register(options);
			break;
		case SHOW:
			showCredential(options);
			break;
		case POST:
			postMessage(options);
			break;
		default:
			throw new IllegalArgumentException("Unrecognized command: " + command.name());
		}
	}
	
	private void displayHelp() {
		say("");
		say("Commands for offline keystoreFile:");
		say("%s: Import a certificate.", Command.IMPORT);
		say("%s: Initialize the keystore.", Command.INIT);
		say("%s: Get a client cert from the online CA.", Command.REGISTER);
		say("%s: Show the client certificate.", Command.SHOW);
		say("%s: Show the client cert.", Command.REGISTER);

		say("%s: Post a message to the chat server.", Command.POST);
		// say("");
		// say("Command options:");
		say("");
		say("Command-line options:");
		say("--%s: Client keystoreFile.", Option.KEYSTORE);
		say("--%s: Client truststoreFile.", Option.TRUSTSTORE);
		say("--%s: Properties file with keystore and truststore passwords.", Option.PASSWORD_FILE);
		say("--%s: Certificate authority base URI.", Option.CA_URI);
		say("--%s: Chat server base URI.", Option.SERVER_URI);
		say("--%s: Message sender name.", Option.SENDER_NAME);
		say("--%s: Message sender password (for CA authentication).", Option.SENDER_PASSWORD);
		say("--%s: Distinguished name for client certificate.", Option.SENDER_DN);
		say("--%s: PEM file containing a certificate.", Option.CERT_FILE);
		say("--%s: Name of a file containing a script to execute.", Option.SCRIPT_FILE);
		say("");
		flush();
	}
	
	/**
	 * Initialize the keystore with a self-signed cert.
	 * @param options
	 * @throws Exception
	 */
	private void initKeystore(Map<Option,String> options) throws Exception {
		
		String senderDn = options.get(Option.SENDER_DN);
		if (senderDn == null) {
			reporter.error("Failed to specify sender DN on the command line!");
			return;
		} 
		
		long duration = getDuration(options, CLIENT_CERT_DURATION);
		
		clientCerts.genClientRoot(senderDn, duration);
	}
	
	/**
	 * Initialize the keystore with a self-signed cert.
	 * @param options
	 * @throws Exception
	 */
	private void initTruststore(Map<Option,String> options) throws Exception {
		
		String certFilename = options.get(Option.CERT_FILE);
		if (certFilename == null) {
			reporter.error("Failed to specify the PEM file with the root CA cert on the command line!");
			return;
		}
		File certFile = new File(certFilename);
		if (!certFile.exists()) {
			reporter.error("Certificate file does not exist: "+certFilename);
			return;
		}
		
		clientCerts.importCaCert(certFile);
	}
	
	/**
	 * Get client cert signed by online CA.
	 * @param options
	 * @throws Exception
	 */
	private void register(Map<Option, String> options) throws Exception {
		
		String certAuthAddress = options.get(Option.CA_URI);
		URI caUri;
		if (certAuthAddress != null) {
			caUri = URI.create(certAuthAddress);
		} else {
			reporter.error("Failed to specify the CA URI on the command line!");
			return;
		}

		String senderName = options.get(Option.SENDER_NAME);
		if (senderName == null) {
			reporter.error("Failed to specify sender name on the command line!");
			return;
		}

		String password = options.get(Option.SENDER_PASSWORD);
		if (password == null) {
			reporter.error("Failed to specify sender password on the command line!");
			return;
		}

		String clientDns = options.get(Option.DNS_NAME); // May be null

		long duration = getDuration(options, CLIENT_CERT_DURATION);

		ChatClient client = new ChatClient(caUri, clientCerts.getTrustStore(), senderName, password.toCharArray());

		String csr = clientCerts.genClientCSR(clientDns);

		GenClientCertRequest request = new GenClientCertRequest();
		request.setClientDns(clientDns);
		request.setDuration(duration);
		request.setCsr(csr);

		GenClientCertResponse response = client.register(request);
				
		if (response == null) {
			return;
		}

		logger.info("Updating client keystore with client cert from CA.");
		clientCerts.importClientCert(response.getCert().getBytes(StringUtils.CHARSET));

	}
	
	private void showCredential(Map<Option,String> options) throws Exception {
		
		clientCerts.showClientCert();
		
	}
	
	/**
	 * Post a message to the chat server.
	 * @param options
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private void postMessage(Map<Option,String> options) throws IOException, GeneralSecurityException {

		String serverAddress = options.get(Option.SERVER_URI);
		URI serverUri;
		if (serverAddress != null) {
			serverUri = URI.create(serverAddress);
		} else {
			reporter.error("Failed to specify the server URI on the command line!");
			return;
		}
		
		String senderName = options.get(Option.SENDER_NAME);
		if (senderName == null) {
			reporter.error("Failed to specify sender name on the command line!");
			return;
		}
		
		System.out.print("Message: ");
		BufferedReader rd = new BufferedReader(new InputStreamReader(System.in, StringUtils.CHARSET));
		String text = rd.readLine();
		if (text == null || text.isEmpty()) {
			say("You must provide the text of the message to post.");
			return;
		}

		ChatClient client = new ChatClient(serverUri, clientCerts.getKeyStore(), clientCerts.getKeyPassword(), clientCerts.getTrustStore());

		client.postMessage(senderName, text);
		
		int rc = client.postMessage(senderName, text);
		reporter.say("Response status: "+rc);
	}
	
	
	public static void main(String[] args) {

		/*
		 * Bootstrap a CDI container (for CertsService injection)
		 */
			
		try (WeldContainer container = new Weld().disableDiscovery().addBeanClasses(CertsService.class, ClientCerts.class).initialize()) {

			App app = new App(container.select(ClientCerts.class).get());

			Driver<Command, Option> driver = new Driver<Command, Option>(app.getReporter(), app);

			try {
				app.execute(driver, args);
			} catch (Exception e) {
				// reporter.error(e.getMessage(), e);
				logger.log(Level.SEVERE, "Uncaught exception.", e);
			}

		}

	}

//	{
//		Security.addProvider(new BouncyCastleProvider());
//	}

	public App(ClientCerts clientCerts) {
		
		this.reporter = Reporter.createReporter();
		
		this.clientCerts = clientCerts;

		commands = new HashMap<String, Command>();
		for (Command command : Command.values()) {
			commands.put(command.value(), command);
		}
				
		options = new HashMap<String, Option>();
		for (Option option : Option.values()) {
			options.put(option.value(), option);
		}
		
		Security.addProvider(new BouncyCastleProvider());
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
	
	protected long getDuration(Map<Option, String> options, long defaultDuration) {
		String duration = options.get(Option.DURATION);
		if (duration == null) {
			return defaultDuration;
		}
		return Long.parseLong(duration);
	}
	
	
	private void initialize(Map<Option,String> options) throws IOException, GeneralSecurityException {
		
		File passwordsFile;
		String passwords = options.get(Option.PASSWORD_FILE);
		if (passwords != null) {
			passwordsFile = new File(passwords);
		} else {
			passwordsFile = new File(PASSWORDS_FILENAME);
		}
		if (!passwordsFile.exists()) {
			throw new IOException("Missing password file: "+passwordsFile.getAbsolutePath());
		}
		
		File keystoreFile;
		String keystoreFileName = options.get(Option.KEYSTORE);
		if (keystoreFileName != null) {
			keystoreFile = new File(keystoreFileName);
		} else {
			keystoreFile = new File(CLIENT_KEYSTORE_FILENAME);
		}
		
		File truststoreFile;
		String truststoreFileName = options.get(Option.TRUSTSTORE);
		if (truststoreFileName != null) {
			truststoreFile = new File(truststoreFileName);
		} else {
			truststoreFile = new File(CLIENT_TRUSTSTORE_FILENAME);
		}

		clientCerts.initKeystores(passwordsFile, keystoreFile, truststoreFile);
						
	}
	
	
}
