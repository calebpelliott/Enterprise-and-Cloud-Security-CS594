package edu.stevens.cs594.util;

public class ExceptionWrapper {
	
	public static <E extends Exception, W extends Exception> W wrap(Class<W> wc, E e) {
		try {
			W w = wc.newInstance();
			w.initCause(e);
			return w;
		} catch (Exception iae) {
			IllegalStateException e2 = new IllegalStateException("Illegal state exception while wrapping an exception");
			e2.initCause(iae);
			throw e2;
		}
	}

}
