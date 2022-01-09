package edu.stevens.cs594.chat.service.ejb;

import java.security.GeneralSecurityException;

import javax.xml.bind.annotation.XmlRootElement;

public interface IPkiService {
	
	@XmlRootElement
	public static class GenClientCertRequest {
		
		private String csr;
		private String clientDns;
		private long duration;
		
		public String getCsr() {
			return csr;
		}
		public void setCsr(String csr) {
			this.csr = csr;
		}
		public String getClientDns() {
			return clientDns;
		}
		public void setClientDns(String clientDns) {
			this.clientDns = clientDns;
		}
		public long getDuration() {
			return duration;
		}
		public void setDuration(long duration) {
			this.duration = duration;
		}
	}
	
	@XmlRootElement
	public static class GenClientCertResponse {
		
		private String cert;

		public String getCert() {
			return cert;
		}
		public void setCert(String cert) {
			this.cert = cert;
		}
	}

	
	/**
	 * Generate a client cert from a CSR
	 * @param name
	 * 	The principal requesting the client cert, match with the CN in the CSR.
	 * @param webRequest
	 *  Includes encoded CSR, duration
	 * @return
	 * @throws GeneralSecurityException
	 */
	public GenClientCertResponse genClientCert(String name, GenClientCertRequest webRequest) throws GeneralSecurityException;
		
}
