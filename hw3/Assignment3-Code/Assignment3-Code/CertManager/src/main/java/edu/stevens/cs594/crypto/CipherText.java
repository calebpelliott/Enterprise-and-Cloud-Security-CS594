package edu.stevens.cs594.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;

import edu.stevens.cs594.util.StringUtils;


public class CipherText {
	
	@SuppressWarnings("unused")
	private final static String TAG = CipherText.class.getCanonicalName();
	
	private byte[] content;

	public CipherText(byte[] cipherText, int ctLength, byte[] iv) {
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			DataOutputStream os = new DataOutputStream(bos);
			StringUtils.writeBlob(os, iv);
			os.writeInt(ctLength);
			os.write(cipherText, 0, ctLength);
			content = bos.toByteArray();
			os.close();
		} catch (IOException e) {
			throw new IllegalStateException("IO exception while writing ciphertext to byte array.", e);
		}
	}
	
	public CipherText(IntCipherText enc) {
		this(enc.cipherText, enc.ctLength, enc.randBytes);
	}
	
	public IntCipherText internal() throws GeneralSecurityException {
		try {
			ByteArrayInputStream bis = new ByteArrayInputStream(content);
			DataInputStream in = new DataInputStream(bis);
			byte[] randBytes = StringUtils.readBlob(in);
			int ctLength = in.readInt();
			byte[] cipherText = new byte[ctLength];
			in.read(cipherText);
			return new IntCipherText(cipherText, ctLength, randBytes);
		} catch (IOException e) {
			throw new IllegalStateException("IO exception while reading ciphertext from byte array.", e);
		}
	}
	
	private Base64.Encoder encoder;
	
	private Base64.Decoder decoder;
	
	{
		encoder = Base64.getEncoder();
		decoder = Base64.getDecoder();
	}
	
	public CipherText(String s) {
		content = decoder.decode(s);
	}
	
	public CipherText(byte[] b) {
		content = b;
	}
	
	@Override
	public String toString() {
		return encoder.encodeToString(content);
	}
	
}