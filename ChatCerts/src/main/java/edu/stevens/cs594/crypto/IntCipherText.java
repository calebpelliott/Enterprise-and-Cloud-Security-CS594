package edu.stevens.cs594.crypto;

import java.security.GeneralSecurityException;

public class IntCipherText {
	
	@SuppressWarnings("unused")
	private final static String TAG = IntCipherText.class.getCanonicalName();

	/* 
	 * randBytes may be salt (for hashed password) or iv (for encrypted data)
	 */

	public final byte[] cipherText;
	
	public final int ctLength;

	public final byte[] randBytes;
	
	public IntCipherText(byte[] cipherText, int ctLength, byte[] randBytes) {
		this.cipherText = cipherText;
		this.ctLength = ctLength;
		this.randBytes = randBytes;
	}
	
	/**
	 * Internal/external
	 */
	
	public CipherText external() {
		return new CipherText(this);
	}
	
	public static String toString(IntCipherText enc) {
		return new CipherText(enc).toString();
	}
	
	public static IntCipherText fromString(String cipherText) {
		try {
			if (cipherText == null) {
				return null;
			} else {
				return new CipherText(cipherText).internal();
			}
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("Security exception while internalizing ciphertext.");
		}
	}
	
}