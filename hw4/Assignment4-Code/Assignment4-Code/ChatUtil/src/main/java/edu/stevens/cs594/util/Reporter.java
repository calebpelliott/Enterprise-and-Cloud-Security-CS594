package edu.stevens.cs594.util;

import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Reporter {

	public static enum Severity {
		DEBUG, INFO, WARNING, ERROR
	}

	private boolean valid = true;

	private Severity level = Severity.WARNING;
	
	private PrintWriter output;
	
	private PrintWriter error;
	
	// private Logger logger;
	
	public void setLevel(Severity lev) {
		this.level = lev;
	}

	public boolean isDebugLevel() {
		switch (level) {
		case DEBUG:
			return true;
		default:
			return false;
		}
	}

	public boolean isInfoLevel() {
		switch (level) {
		case DEBUG:
		case INFO:
			return true;
		default:
			return false;
		}
	}

	public boolean isWarningLevel() {
		switch (level) {
		case DEBUG:
		case INFO:
		case WARNING:
			return true;
		default:
			return false;
		}
	}

	public boolean isErrorLevel() {
		return true;
	}

	public boolean isValid() {
		return valid;
	}

	public void say(String msg) {
		output.println(msg);
		output.flush();
	}

	public void shout(String msg) {
		error.println(msg);
		error.flush();
	}

	public void debug(String msg) {
		if (isDebugLevel())
			say("D " + msg);
	}

	public void info(String msg) {
		if (isInfoLevel())
			say("I " + msg);
	}

	public void warning(String msg) {
		if (isWarningLevel())
			say("W " + msg);
	}

	public void error(String msg) {
		error(msg, null, null);
	}
	
	public void error(String msg, Exception e) {
		error(msg, null, e);
	}
	
	public void error(String msg, Logger logger, Exception e) {
		if (isErrorLevel()) {
			valid = false;
			shout("E " + msg);
			reportException(e);
		}
		logMessage(logger, Level.SEVERE, msg, e);
	}
	
	private void reportException(Exception e) {
		if (e != null) {
			e.printStackTrace(error);
		}		
	}
	
	private void logMessage(Logger logger, Level level, String msg, Exception e) {
		if (logger != null) {
			if (e != null) {
				logger.log(level, msg, e);
			} else {
				logger.log(level, msg);
			}
		}
	}
	
	public void flush() {
		output.flush();
		error.flush();
	}
	
	private Reporter() {
		try {
			output = new PrintWriter(new OutputStreamWriter(System.out, StringUtils.CHARSET));
			error = new PrintWriter(new OutputStreamWriter(System.err, StringUtils.CHARSET));
		} catch (UnsupportedEncodingException e) {
			throw ExceptionWrapper.wrap(IllegalStateException.class, e);
		}
	}
	
	public static Reporter createReporter() {
		return new Reporter();
	}
	
//	public void setLogger(Logger logger) {
//		this.logger = logger;
//	}

}
