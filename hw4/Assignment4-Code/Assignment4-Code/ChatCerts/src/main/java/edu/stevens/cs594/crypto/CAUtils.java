package edu.stevens.cs594.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import edu.stevens.cs594.util.DateUtils;
import edu.stevens.cs594.util.ExceptionWrapper;

public class CAUtils {
	
	private static final String TAG = CAUtils.class.getCanonicalName();
	private static final Logger logger = Logger.getLogger(TAG);
	
	/**
	 * For use by the server-side CA.
	 */
	
	public final static KeyUsage CA_USAGE;

	public final static KeyUsage END_USAGE;
	
	public final static KeyUsage CODE_SIGN_USAGE;
	
	public final static KeyUsage ENCRYPT_USAGE;
	
	public final static ExtendedKeyUsage CLIENT_USAGE_EXT;

	public final static ExtendedKeyUsage SERVER_USAGE_EXT;

	public final static ExtendedKeyUsage CODE_SIGN_USAGE_EXT;

	static {
		CA_USAGE = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign);
		END_USAGE = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.keyEncipherment);
		CODE_SIGN_USAGE = new KeyUsage(KeyUsage.digitalSignature);
		ENCRYPT_USAGE = new KeyUsage(KeyUsage.keyEncipherment);
		CLIENT_USAGE_EXT = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
		SERVER_USAGE_EXT = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);
		CODE_SIGN_USAGE_EXT = new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning);
	}
	
	public static X500Name toX500Name(String name) {
		return new X500Name(RFC4519Style.INSTANCE, name);
	}
	
	public static X500Name toX500Name(X500Principal principal) {
		// return X500Name.getInstance(principal.getEncoded());
		return toX500Name(principal.getName());
	}
	
	public static String getCN(X500Name dn) {
		if (dn == null) {
			return null;
		}

		RDN[] rdns = dn.getRDNs(BCStyle.CN);
		if (rdns.length == 0) {
			return null;
		}

		return rdns[0].getFirst().getValue().toString();
	}

	/**
	 * Certificate signer.
	 */
	public static ContentSigner getContentSigner(PrivateKey privateKey) throws OperatorCreationException{
		return new JcaContentSignerBuilder("SHA512withRSA")
				.setProvider("BC")
				.build(privateKey);
	}

	/**
	 * Certificate verifier.
	 */
	public static ContentVerifierProvider getContentVerifier(PublicKey publicKey) throws OperatorCreationException {
		return new JcaContentVerifierProviderBuilder()
				.setProvider("BC")
				.build(publicKey);
	}
	
	/**
	 * Build a self-signed v1 certificate to bootstrap a client.
	 */
	public static X509Certificate createClientRootCert(long id, X500Name clientDn, KeyPair keyPair,
			long durationHours) throws GeneralSecurityException {
		// TODO generate self-signed v1 certificate
		return null;
	}
	
	/**
	 * Build a self-signed v3 certificate for the root CA.
	 */
	public static X509Certificate createCaRootCert(long id, X500Name caName, KeyPair keyPair,
			long durationHours) throws GeneralSecurityException {
		// TODO generate root CA self-signed v3 cert
		return null;
	}
	
	/**
	 * Create an intermediate or end-entity certificate.
	 */
	private static X509Certificate createCert(long id, PrivateKey issuerKey, X509Certificate issuerCert,
			X500Name subjectName, PublicKey subjectKey, BasicConstraints basicConstraints, KeyUsage usage,
			ExtendedKeyUsage extendedUsage, GeneralNames sans, long durationHours) throws GeneralSecurityException {
		try {
			// TODO create x509v3CertificateBuilder, add extensions as described in lectures
			X509v3CertificateBuilder certBuilder = null;
			
			if (extendedUsage != null) {
				// Make this non-critical to avoid errors on some platforms.
				certBuilder.addExtension(Extension.extendedKeyUsage, false, extendedUsage);
			}
			
			if (sans != null) {
				certBuilder.addExtension(Extension.subjectAlternativeName, false, sans);
			}
			
			ContentSigner signer = getContentSigner(issuerKey);
			return new JcaX509CertificateConverter()
				.setProvider("BC")
				.getCertificate(certBuilder.build(signer));
		} catch (CertIOException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (OperatorCreationException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
	/**
	 * Create an intermediate certificate for online CA.
	 */
	public static X509Certificate createOnlineCaCert(long id, PrivateKey issuerKey, X509Certificate issuerCert,
			X500Name subjectName, PublicKey subjectKey, long durationHours) throws GeneralSecurityException {
		BasicConstraints basicConstraints = new BasicConstraints(0);
		return createCert(id, issuerKey, issuerCert, subjectName, subjectKey, basicConstraints, CA_USAGE, null, null, durationHours);
	}
	
	/**
	 * Create an end-user certificate for the server.
	 */
	public static X509Certificate createServerCert(long id, PrivateKey issuerKey, X509Certificate issuerCert,
			X500Name subjectName, String serverDNS, PublicKey subjectKey, long durationHours) throws GeneralSecurityException {
		GeneralName san = new GeneralName(GeneralName.dNSName, serverDNS);
		GeneralNames sans = new GeneralNames(new GeneralName[]{ san });
		BasicConstraints basicConstraints = new BasicConstraints(false);
		return createCert(id, issuerKey, issuerCert, subjectName, subjectKey, basicConstraints, END_USAGE,
				SERVER_USAGE_EXT, sans, durationHours);
	}
	
	/**
	 * Request a certificate from the CA certifying our signature.
	 */
	public static PKCS10CertificationRequest createCSR(X500Name subject, KeyPair keyPair, 
			String dnsAddress) throws GeneralSecurityException {
		// TODO Generate CSR
		return null;
	}
	
	/**
	 * Generate a client certificate from a CSR.
	 */
	public static X509Certificate createClientCert(long id, PrivateKey issuerKey, X509Certificate issuerCert,
			PKCS10CertificationRequest csr,  String dnsAddress, long durationHours)
			throws GeneralSecurityException {
		try {
			BasicConstraints basicConstraints = new BasicConstraints(false);
			PublicKey subjectKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();

			ContentVerifierProvider contentVerifier = getContentVerifier(subjectKey);
			if (!csr.isSignatureValid(contentVerifier)) {
				logger.log(Level.WARNING, "Bad signature on certificate signing request: " + csr.getSubject());
				return null;
			}
			
			// TODO generate client cert from the CSR (add DNS SAN if dnsAddress is provided)

			return null;

		} catch (NoSuchAlgorithmException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (OperatorCreationException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		} catch (PKCSException e) {
			throw ExceptionWrapper.wrap(GeneralSecurityException.class, e);
		}
	}
	
}
