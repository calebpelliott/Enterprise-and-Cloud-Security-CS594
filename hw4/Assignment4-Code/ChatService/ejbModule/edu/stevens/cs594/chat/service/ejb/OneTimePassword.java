/*
 * Taken from: https://oneminutedistraction.wordpress.com/tag/java-jsf-totp-glassfish-javaee-security-faces-flow/
 */
package edu.stevens.cs594.chat.service.ejb;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

/**
 *
 * @author project
 */
public class OneTimePassword {
	
	private static final Logger logger = Logger.getLogger(OneTimePassword.class.getCanonicalName());

	public static final String MAC_ALGORITHM = "HmacSHA1";

	public static final int WINDOW = 3;

	public static final String GOOGLE_URL = "https://chart.googleapis.com/chart?chs=250x250&cht=qr&chl=otpauth://totp/";

	private final static SecureRandom random = new SecureRandom();

	public static final class OtpAuth {

		private String keyUri;
		private String secretBase32;

		public String getKeyUri() {
			return keyUri;
		}

		public void setKeyUri(String keyUri) {
			this.keyUri = keyUri;
		}

		public String getSecretBase32() {
			return secretBase32;
		}

		public void setSecretBase32(String secretBase32) {
			this.secretBase32 = secretBase32;
		}

	}

	public static OtpAuth generateOtpAuth(String subject, String issuer) {
		byte[] secret = new byte[10];
		random.nextBytes(secret);
		return generateOtpAuth(subject, issuer, secret);
	}

	private static OtpAuth generateOtpAuth(String subject, String issuer, byte[] secret) {

		try {

			OtpAuth result = new OtpAuth();

			byte[] encodedSecret = new Base32().encode(secret);
			String secretBase32 = new String(encodedSecret, MessageService.CHARSET);
			result.setSecretBase32(secretBase32);
			
			/*
			 *  TODO set the key URI.  Use URLEncoder to encode the issuer and subject, using UTF-8 charset.
			 */
			String issuerEnc = URLEncoder.encode(issuer, MessageService.CHARSET);
			String subjectEnc = URLEncoder.encode(subject, MessageService.CHARSET);
			String keyUri = "otpauth://totp/" + issuerEnc + ":" + subjectEnc + "?secret=" + secretBase32 + "&issuer=" + issuerEnc;
			result.setKeyUri(keyUri);

			return result;

		} catch (UnsupportedEncodingException ex) {
			throw new IllegalStateException("Creating OTP auth", ex);
		}

	}

	public static boolean checkCode(String otpSecret, Long code, long t) {
		
		/*
		 * If this is null, there is no 2FA for this user.
		 */
		if (otpSecret == null) {
			logger.info("Skipping 2FA for test user (null secret)");
			return true;
		}
		
		/*
		 * Did the user provide a code during login?
		 */
		if (code == null) {
			return false;
		}
		
		long icode = code;

		try {

			Base32 codec = new Base32();
			byte[] decodedKey = codec.decode(otpSecret);
			long time = t / 30000;

			// Window is used to check codes generated in the near past.
			// You can use this value to tune how far you're willing to go.
			for (int i = -WINDOW; i <= WINDOW; ++i) {
				long hash = verifyCode(decodedKey, time + (i * 30000));
				if (hash == icode) {
					return true;
				}
			}

			// The validation code is invalid.
			return false;

		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			throw new IllegalStateException("checkCode(secret,code,t)", e);
		}
	}

	private static int verifyCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
		byte[] data = new byte[8];
		long value = t;
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		SecretKeySpec signKey = new SecretKeySpec(key, MAC_ALGORITHM);
		Mac mac = Mac.getInstance(MAC_ALGORITHM);
		mac.init(signKey);
		byte[] hash = mac.doFinal(data);

		int offset = hash[20 - 1] & 0xF;

		// We're using a long because Java hasn't got unsigned int.
		long truncatedHash = 0;
		for (int i = 0; i < 4; ++i) {
			truncatedHash <<= 8;
			// We are dealing with signed bytes:
			// we just keep the first byte.
			truncatedHash |= (hash[offset + i] & 0xFF);
		}

		truncatedHash &= 0x7FFFFFFF;
		truncatedHash %= 1000000;

		return (int) truncatedHash;
	}

}
