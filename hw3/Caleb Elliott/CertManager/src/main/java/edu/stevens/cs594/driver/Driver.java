package edu.stevens.cs594.driver;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Logger;

import edu.stevens.cs594.util.Reporter;
import edu.stevens.cs594.util.StringUtils;


/**
 * A driver class for a command-line interface.
 * Command: recognized commands (may be batched in a file)
 * Option: command-line options (may be parameterized by an arg)
 */
public class Driver<Command extends Enum<Command>, Option extends Enum<Option>> {
	
	public interface Callback<Command,Option> {
		public Command lookupCommand(String arg);
		public Option lookupOption(String arg);
		public boolean isParameterized(Option arg);
		public void execute(Command command, Map<Option,String> options) throws Exception;
	}
	
	// Quit command
	public static final String QUIT_COMMAND = "quit";
	
	// For options that do not take a parameter:
	public static final String DEFAULT_ARG_VALUE = "";
	
	// Character signifying a script on a command line
	public static final String SCRIPT_TOKEN = "@";
	
	private boolean isScript(String s) {
		return s.startsWith(SCRIPT_TOKEN);
	}
	
	private String getScriptName(String s) {
		return s.substring(1);
	}
	
	private static final String TAG = Driver.class.getSimpleName();
	
	@SuppressWarnings("unused")
	private static final Logger logger = Logger.getLogger(TAG);
	
	private Reporter reporter;
	
	private Callback<Command,Option> callback;
	
	public Driver(Reporter reporter, Callback<Command, Option> callback) {
		this.reporter = reporter;
		this.callback = callback;
	}

	private static final String PROMPT_PROPERTIES = "driver";
	
	private static final String WARNING_INTERACTIVE = "warning.interactive";
	
	// Prompts for the dialog for a read-eval-print loop
	private static ResourceBundle prompts;
	
	private static final String WarningInteractive;
	
	static {
		prompts = ResourceBundle.getBundle(PROMPT_PROPERTIES);
		if (prompts == null) {
			throw new IllegalStateException("Missing resource bundle: "+PROMPT_PROPERTIES);
		}
		WarningInteractive = prompts.getString(WARNING_INTERACTIVE);
	}
	
	public Command parseCommand(String[] optionStrs, Map<Option,String> options) throws Exception {
		
		// Empty argument line?
		if (optionStrs.length == 0) {
			return null;
		}
		
		if (QUIT_COMMAND.equals(optionStrs[0])) {
			return null;
		}

		// Embedded script?
		if (isScript(optionStrs[0])) {
			File script = new File(getScriptName(optionStrs[0]));
			BufferedReader rd = new BufferedReader(new InputStreamReader(new FileInputStream(script), StringUtils.CHARSET));
			batch(rd);
			return null;
		}

		// The command should be the first token on the line.
		Command command = callback.lookupCommand(optionStrs[0]);
		if (command == null) {
			throw new IOException("Unrecognized command: " + optionStrs[0]);
		}
		
		parseOptions(1, optionStrs, options);
		
		return command;
	}
	
	public void parseOptions(String[] optionStrs, Map<Option,String> options) throws IOException {
		
		parseOptions(0, optionStrs, options);
		
	}
	
	private void parseOptions(int ix, String[] optionStrs, Map<Option,String> options) throws IOException {
		Option option;
		String optionStr;
		String argStr;
		boolean success = true;

		while (ix < optionStrs.length) {
			optionStr = null;
			argStr = null;
			if (optionStrs[ix].startsWith("--")) {
				optionStr = optionStrs[ix];
				ix++;
			} else {
				reporter.error("Expecting option, encountered " + optionStrs[ix]);
				success = false;
				ix++;
				continue;
			}
			
			// Is the option recognized?
			option = callback.lookupOption(optionStr.substring(2));
			if (option == null) {
				reporter.error("Unrecognized option: " + optionStr);
				success = false;
				continue;
			}
			
			// Is it an option with an argument?
			if (ix < optionStrs.length && !optionStrs[ix].startsWith("--")) {
				argStr = optionStrs[ix];
				ix++;
				if (!callback.isParameterized(option)) {
					reporter.error("Unexpected argument " + argStr + " for option " + optionStr);
					success = false;
				} else {
					options.put(option, argStr);
				}
				continue;
			}

			// Is there a missing argument for the option?
			if (argStr == null && callback.isParameterized(option)) {
				reporter.error("Missing argument for option " + optionStr);
				success = false;
				continue;
			}
			
			// Valid option with no argument
			options.put(option, DEFAULT_ARG_VALUE);
			
		}
		
		if (!success) {
			throw new IOException("Please fix the command line.");
		}
	}
	
	private String readLine(String prompt) throws IOException {
		Console console = System.console();
		
		//Remove after debug
		//BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
		//String line = bufferedReader.readLine();
		//line = line.trim();
		//Remove after debug
		
		//Include after debug
		if (console == null) {
			throw new IOException(WarningInteractive);
		}
		String line = console.readLine(prompt);
		if (line != null) {
			line = line.trim();
		}
		//Include after debug
		
		return line;
	}

	public void interactive(String prompt) throws Exception {
		String line = this.readLine(prompt);
		while (line != null) {
			String[] optionStrs = line.split("\\s");
			Map<Option, String> args = new HashMap<Option, String>();
			Command command = parseCommand(optionStrs, args);
			if (command != null) {
				callback.execute(command, args);
				line = this.readLine(prompt);
			} else {
				line = null;
			}
		}
	}
	
	public void batch(BufferedReader rd) throws Exception {
		String line = rd.readLine();
		while (line != null) {
			String[] optionStrs = line.split("\\s");
			Map<Option,String> args = new HashMap<Option,String>();
			Command command = parseCommand(optionStrs, args);
			if (command != null) {
				callback.execute(command, args);
				line = rd.readLine();
			} else {
				line = null;
			}
		}
	}
	
}
