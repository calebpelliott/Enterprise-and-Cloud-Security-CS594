package edu.stevens.cs594.util;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.logging.Logger;


public class StringUtils {
	
	@SuppressWarnings("unused")
	private static final Logger logger = Logger.getLogger(StringUtils.class.getCanonicalName());
	
	/*
	 * Byte arrays and character set encoding
	 */
	
	public static final String CHARSET = "UTF-8";
	
	public static String toString(byte[] b) {
		return toString(b, b.length);
	}
	
	public static String toString(byte[] b, int len) {
		try {
			return new String(b, 0, len, CHARSET);
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Unsupported UTF-8 encoding!");
			// return null;
		}
	}

	private static enum TitleCaseState {
		NORMAL, SEPARATOR, TITLE
	}

	@SuppressWarnings("unused")
	private static StringBuilder makeTitleCase(String s) {
		StringBuilder sb = new StringBuilder();
		TitleCaseState state = TitleCaseState.SEPARATOR;
		for (int i=0; i<s.length(); i++) {
			char ch = s.charAt(i);
			switch (state) {
			case NORMAL:
				if (ch=='_') {
					state = TitleCaseState.SEPARATOR;
				} else if (Character.isUpperCase(ch)) {
					sb.append(ch);
					state = TitleCaseState.TITLE;
				} else {
					sb.append(ch);
				}
				break;
			case SEPARATOR:
				if (ch=='_') {
					/* Keep going */ ;
				} else if (Character.isUpperCase(ch)) {
					sb.append(ch);
					state = TitleCaseState.TITLE;
				} else {
					sb.append(Character.toUpperCase(ch));
					state = TitleCaseState.NORMAL;
				}
				break;
			case TITLE:
				if (ch=='_') {
					state = TitleCaseState.SEPARATOR;
				} else if (Character.isUpperCase(ch)) {
					sb.append(Character.toLowerCase(ch));
				} else {
					sb.append(ch);
					state = TitleCaseState.NORMAL;
				}
				break;
			}
		}
		return sb;
	}
	
//	public static String toTitleCase(String tyName) {
//		return makeTitleCase(tyName).toString();
//	}

	public static String getFieldLabel(String tyName) {
//		StringBuilder sb = makeTitleCase(tyName);
//		StringBuilder sb = new StringBuilder(tyName);
//		sb.setCharAt(0, Character.toLowerCase(sb.charAt(0)));
//		return sb.toString();
		return tyName;
	}
	
//	public static String getFieldLabel(Identity id) {
//		return getFieldLabel(id.getId());
//	}
	
	public static String toTitleCase(String tyName) {
//		StringBuilder sb = makeTitleCase(tyName);
		StringBuilder sb = new StringBuilder(tyName);
		sb.setCharAt(0, Character.toUpperCase(sb.charAt(0)));
		return sb.toString();
	}
	
	public static String toUpperCase(String s) {
		return s.toUpperCase(Locale.US);
	}

	public static String toLowerCase(String s) {
		return s.toLowerCase();
	}

	public static <T> String toString(Collection<T> set) {
		StringBuffer sb = new StringBuffer("[");
		int j=0;
		for (T s : set) {
			if (j > 0) {
				sb.append(',');
			}
			sb.append(s==null ? "null" : s.toString());
			j++;
		}
		sb.append(']');
		return new String(sb);
	}
	
	public static String toString(char[] b) {
		return toString(b, b.length);
	}
	
	public static String toString(char[] b, int len) {
		return new String(b, 0, len);
	}
	
	public static boolean isEqual(char[] s1, char[] s2) {
		if (s1.length != s2.length) {
			return false;
		}
		for (int ix=0; ix<s1.length; ix++) {
			if (s1[ix] != s2[ix]) {
				return false;
			}
		}
		return true;
	}
	
	public static byte[] toBytes(String s) {
		try {
			return s.getBytes(CHARSET);
		} catch (UnsupportedEncodingException e) {
			throw ExceptionWrapper.wrap(IllegalStateException.class, e);
		}
	}
	
	public static byte[] toBytes(char[] s) {
		return toBytes(String.valueOf(s));
	}
	
	public static int lookup(String key, String[] keys) {
		for (int i=0; i< keys.length; i++) {
			if (key.equals(keys[i])) {
				return i;
			}
		}
		return -1;
	}
	
	public static int lookup(String key, List<String> keys) {
		int length = keys.size();
		for (int i=0; i< length; i++) {
			if (key.equals(keys.get(i))) {
				return i;
			}
		}
		return -1;
	}
	
	public static boolean contains(List<String> keys, String key) {
		return lookup(key, keys) >= 0;
	}
	
	public static char[] toCharArray(byte[] b) {
		return toCharArray(b, b.length);
	}
	
	public static char[] toCharArray(byte[] b, int len) {
		return toString(b, len).toCharArray();
	}
	
	public static char[] readPassword(DataInputStream in) throws IOException {
		byte[] b = new byte[in.readInt()];
		in.read(b);
		char[] c = toCharArray(b);
		Arrays.fill(b, (byte)0);
		return c;
	}
	
	public static void writePassword(DataOutputStream out, char[] password) throws IOException {
		byte[] b = toBytes(password);
		out.writeInt(b.length);
		out.write(b);
		Arrays.fill(b, (byte)0);
	}

	
	/*
	 * URIs
	 */

	public static URI getNullableUri(String value) {
		if (value == null) {
			return null;
		} else {
			return URI.create(value);
		}
	}

	public static URI readNullableUri(DataInputStream in) throws IOException {
		if (in.readBoolean()) {
			return URI.create(in.readUTF());
		} else {
			return null;
		}
	}
	
	public static void writeNullableUri(DataOutputStream out, URI u) throws IOException {
		if (u == null) {
			out.writeBoolean(false);
		} else {
			out.writeBoolean(true);
			out.writeUTF(u.toString());
		}
	}
	
	private static final String URN_PREFIX = "urn:uuid:";
	private static final int URN_PREFIX_LENGTH = URN_PREFIX.length();
	
	public static URI toUrn(UUID uuid) {
		return URI.create(URN_PREFIX + uuid.toString());
	}
	
	public static String fromUrn(URI urn) {
		return urn.toString().substring(URN_PREFIX_LENGTH);
	}
	
	/*
	 * URLs
	 */

	public static boolean isValidUrl(String url) {	
	    try {
	        new URL(url);
	        return true;
	    } catch (MalformedURLException e) {
	        return false;
	    }
	}

	public static URL getNullableUrl(String value) {
		if (value == null) {
			return null;
		} else {
			try {
				return new URL(value);
			} catch (MalformedURLException e) {
				throw ExceptionWrapper.wrap(IllegalStateException.class, e);
			}
		}
	}

	public static URL readNullableUrl(DataInputStream in) throws IOException {
		if (in.readBoolean()) {
			String value = in.readUTF();
			try {
				return new URL(value);
			} catch (MalformedURLException e) {
				throw ExceptionWrapper.wrap(IllegalStateException.class, e);
			}
		} else {
			return null;
		}
	}
	
	public static void writeNullableUrl(DataOutputStream out, URL u) throws IOException {
		if (u == null) {
			out.writeBoolean(false);
		} else {
			out.writeBoolean(true);
			out.writeUTF(u.toString());
		}
	}
	
	public static URL withAppendedPath(URL u, String segment) {
		try {
			return new URL(u.toString() + "/" + segment);
		} catch (MalformedURLException e) {
			throw ExceptionWrapper.wrap(IllegalStateException.class, e);
		}
	}
	
	/*
	 * UUIDs
	 */
	
	public static UUID getNullableUUID(String value) {
		if (value == null) {
			return null;
		} else {
			return UUID.fromString(value);
		}
	}

	public static UUID readNullableUUID(DataInputStream in) throws IOException {
		if (in.readBoolean()) {
			return UUID.fromString(in.readUTF());
		} else {
			return null;
		}
	}
	
	public static void writeNullableUUID(DataOutputStream out, UUID u) throws IOException {
		if (u == null) {
			out.writeBoolean(false);
		} else {
			out.writeBoolean(true);
			out.writeUTF(u.toString());
		}
	}
	
	/*
	 * Blobs
	 */
	
	public static byte[] readBlob(DataInputStream in) throws IOException {
		byte[] b = new byte[in.readInt()];
		in.readFully(b, 0, b.length);
		return b;
	}
	
	public static void writeBlob(DataOutputStream out, byte[] b) throws IOException {
		out.writeInt(b.length);
		out.write(b);
	}

	public static byte[] readNullableBlob(DataInputStream in) throws IOException {
		if (in.readBoolean()) {
			return readBlob(in);
		} else {
			return null;
		}
	}
	
	public static void writeNullableBlob(DataOutputStream out, byte[] b) throws IOException {
		if (b == null) {
			out.writeBoolean(false);
		} else {
			out.writeBoolean(true);
			writeBlob(out, b);
		}
	}
	
	public static boolean isEqualBlobs(byte[] a, byte[] b) {
		if (a.length != b.length) {
			return false;
		}
		for (int i=0; i<a.length; i++) {
			if (a[i] != b[i]) {
				return false;
			}
		}
		return true;
	}
	
	/*
	 * For certificate chains.  We assume non-null chains.
	 */
	
	public static byte[][] readChain(DataInputStream in) throws IOException {
		int chainLength = in.readInt();
		byte[][] chain = new byte[chainLength][];
		for (int i=0; i<chainLength; i++) {
			chain[i] = readBlob(in);
		}
		return chain;
	}
	
	public static void writeChain(DataOutputStream out, byte[][] chain) throws IOException {
		out.writeInt(chain.length);
		for (int i=0; i<chain.length; i++) {
			writeBlob(out, chain[i]);
		}
	}
	
	/*
	 * Strings
	 */
	
	public static String readNullableString(DataInputStream in) throws IOException {
		if (in.readBoolean()) {
			return in.readUTF();
		} else {
			return null;
		}
	}
	
	public static void writeNullableString(DataOutputStream out, String s) throws IOException {
		if (s == null) {
			out.writeBoolean(false);
		} else {
			out.writeBoolean(true);
			out.writeUTF(s);
		}
	}
	
	public static boolean isEmptyInput(String s) {
		return s == null || s.length() == 0;
	}
	
	public static boolean isEmptyInput(Object s) {
		return s == null || (s instanceof String && ((String)s).length() == 0);
	}

}
