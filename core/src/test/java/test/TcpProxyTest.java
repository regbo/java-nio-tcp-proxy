package test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Optional;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.lfp.tls.proxy.core.TcpDynamicProxyConfig;
import com.lfp.tls.proxy.core.TcpProxyLFP;

public class TcpProxyTest {

	public static void main(String[] args) throws IOException, GeneralSecurityException, InterruptedException {
		TcpDynamicProxyConfig config = TcpDynamicProxyConfig.builder().withLocalPort(6969)
				.withRemoteSocketAddressGenerator(op -> {
					return new InetSocketAddress("localhost", 8181);
				}).build();
		var sslContext = createSSLContext();
		TcpProxyLFP proxy = new TcpProxyLFP(config, op -> {
			return Optional.of(sslContext);
		});
		proxy.start();
		System.out.println("started");
		Thread.currentThread().join();
	}

	public static SSLContext createSSLContext() throws IOException, GeneralSecurityException {
		Security.addProvider(new BouncyCastleProvider());

		// generated here https://www.selfsignedcertificate.com/

		String privateKey = "-----BEGIN RSA PRIVATE KEY-----\r\n"
				+ "MIIEowIBAAKCAQEA0Tctes9u4cf4/BlOi0W2n4oVbqXhfT+SGRP7mRidxjB8imay\r\n"
				+ "Q8Oe2Sc5+6uZOoEVrzcs+OKCXuszlG7E2tSnEjH6PUrfOq5yHhjvVNjvWVH8Tkp7\r\n"
				+ "FpVzLRf1n172DNqpM0h2c+5pr1tTUKo3hWVxQXiEX+whhKgJjV6k/IH4x4SSEPti\r\n"
				+ "Ema6lkKXYdONiuEb3t+iUWMualzjwZaHXkYqpAqabecTjUy3Uoxfk6o+LWKSJtoL\r\n"
				+ "Mglzr1/oUWkv6GkyNrR+IS08UE8htger+FcLJwj9EL9YUiyJEGNBUz0sMq506Aq4\r\n"
				+ "2OsvGgFOE3YGYLf92ADOJNzsxJ/YKEgw1jiUKwIDAQABAoIBAF7CAgxUtWD3xLLR\r\n"
				+ "93wnCA78aLaj1Rx4VYCcR2FQ/+zK+y1oVCdTC7hJBv8Q+qa/3oVslSbo2KmLF+KL\r\n"
				+ "xQdkN4OLNU7bgX2/kxpEqumgE9A9zOvc2iEhcXgkGPCk/wZVZzs9/8CEZEOzNmob\r\n"
				+ "nmgBySkhH7ueZJQD08e+7TUc3QPoGtxFJQr0D2xzqPbBxSckA+tA6vUY3SDlxf7Z\r\n"
				+ "TcBMbicaM45pyIr5WU1J3DTFOTd6ptO/AzRDu4n2l1Js8814J59DJH8Ai1SNLrUk\r\n"
				+ "5s+SeOPN5Fp2Yu/6+oJs3wJK3l6SWD62MRkXkulK6wRImos/9yBWJArDKcHZmBFy\r\n"
				+ "PU+joPkCgYEA7F7nd9pGo2lchz8zuDT0GSG0XSh13f7MOLddbF6XXCnhKbXM3+FL\r\n"
				+ "YObe8IP4fTTzXe0xmaVYnzJXUlLLO4Rex6zaf1PmJbgv7oIkLxQKUUNbJ5DXyKEk\r\n"
				+ "+hBiD3PGiG6Yk1c7axvY7GJ06nRm8A8lY9EK1MJeC1plsXqk448ycB0CgYEA4pb4\r\n"
				+ "lwSnVg1MRJpXxKF974nfQsvwh3R3Zjy5sOmjG55SOnUUJdlWGuXOoAjBruwIlmTi\r\n"
				+ "m3zqycMfmibFKNUgAtNgjDUU1tmYKh5Jp1ZbFytQ045aTm1Rz56hlItDiux3ui1f\r\n"
				+ "4saGzZA7Hj6QJSmg3QCPJmfBOVvHNHW21p+C8ucCgYAetfn3DYouAyt9ew26Ok8Y\r\n"
				+ "0NNBY1dlH4zjNZfS07twwxQ5OiDDWd9UWMrQjyUDB5UzN/VA1EXecUj9LjqvofQ6\r\n"
				+ "l0/QSVNWxUadA5W19DGe+1RloKEYtS87ulMzVMSPx2bVhfj3YqfdlrFAIR2axS0D\r\n"
				+ "eg6hNBvJ99XMqHWyB1HzVQKBgEIWvJz3m4MKz+L2jYDphVzXfsnxx88KVkT4k0SZ\r\n"
				+ "cJx+mgc43M6JTIb93j1pMGy/pWWQOVQWpDiC8/W3NyxItVR9qJxcYx6jSrGGMf9f\r\n"
				+ "vaPNW37I92gGlKUU5JX55JJhlC42S9BODUVpuwSARPTB5oxvPFF8U6xSK5EOgGyr\r\n"
				+ "C7ujAoGBAOoVKz7X9+6NJyCP0xJEnA9lOWDj/mIWSsOKviPX/bC8gUttwhDBIUTn\r\n"
				+ "BIftM+k/90AdnvBZYhs7ouG58FLDAEKo6t+1ilJ4A5cS8BmbQU9KkSxVxmd+VUtZ\r\n"
				+ "tng7unC9hxZeEIKV4ghqTwlgYk8lemYu3HctSfmoBdVQKYfaB2pJ\r\n" + "-----END RSA PRIVATE KEY-----\r\n" + "";
		String certificate = "-----BEGIN CERTIFICATE-----\r\n"
				+ "MIIC5zCCAc+gAwIBAgIJAIzswkHM363jMA0GCSqGSIb3DQEBBQUAMCAxHjAcBgNV\r\n"
				+ "BAMTFXRlc3QuMTI3LjAuMC4xLm5pcC5pbzAeFw0yMDA5MTYxNDI1MThaFw0zMDA5\r\n"
				+ "MTQxNDI1MThaMCAxHjAcBgNVBAMTFXRlc3QuMTI3LjAuMC4xLm5pcC5pbzCCASIw\r\n"
				+ "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANE3LXrPbuHH+PwZTotFtp+KFW6l\r\n"
				+ "4X0/khkT+5kYncYwfIpmskPDntknOfurmTqBFa83LPjigl7rM5RuxNrUpxIx+j1K\r\n"
				+ "3zquch4Y71TY71lR/E5KexaVcy0X9Z9e9gzaqTNIdnPuaa9bU1CqN4VlcUF4hF/s\r\n"
				+ "IYSoCY1epPyB+MeEkhD7YhJmupZCl2HTjYrhG97folFjLmpc48GWh15GKqQKmm3n\r\n"
				+ "E41Mt1KMX5OqPi1ikibaCzIJc69f6FFpL+hpMja0fiEtPFBPIbYHq/hXCycI/RC/\r\n"
				+ "WFIsiRBjQVM9LDKudOgKuNjrLxoBThN2BmC3/dgAziTc7MSf2ChIMNY4lCsCAwEA\r\n"
				+ "AaMkMCIwIAYDVR0RBBkwF4IVdGVzdC4xMjcuMC4wLjEubmlwLmlvMA0GCSqGSIb3\r\n"
				+ "DQEBBQUAA4IBAQBnbDf3bnIcw5BgifmeK46BT4tqG/oEhqT1gZeSqnPZeN5fg4fS\r\n"
				+ "OwH9RfqBlMUce6lVPYQgverH0l7R4A7BgnwCVfS0xTed8JqS+gvK5qdmPn0wxOCF\r\n"
				+ "kI1TQZn+5U8UodTsDUTBfl9q8QjCZ2KIXHf2gShsOeu5Ur3AfQQxQk4NRmFPKzKO\r\n"
				+ "6O13mkZwAqbIyUILjwXH3+vD5upkCinsPZD4uc6muQFT27hd0Y3SMqz84fR1Xpbk\r\n"
				+ "wvnr+hjSzL2jKzX+dFDTgPC5ZFPOFXiasxNdNe51YSW/EC5UIPGmbNZtQrPRSKAs\r\n"
				+ "rfT+SROQ2RazCwIMk7MO7DasRNFGeUJO5T+q\r\n" + "-----END CERTIFICATE-----\r\n" + "";
		char[] passphrase = "123456".toCharArray();
		// create a key store
		KeyStore ts = KeyStore.getInstance("JKS");
		KeyStore ks = KeyStore.getInstance("JKS");
		ts.load(null, null);
		ks.load(null, null);
		Certificate[] trustedCerts = readCertificates(certificate);
		{ // read the trused certs
			int index = -1;
			for (Certificate cert : trustedCerts) {
				index++;
				ts.setCertificateEntry("rsa-trusted-2048-" + index, cert);
			}
		}
		// read the private key.
		PrivateKey priKey;
		KeyFactory factory = KeyFactory.getInstance("RSA");
		try (StringReader reader = new StringReader(privateKey); PemReader pemReader = new PemReader(reader)) {
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
			priKey = (RSAPrivateKey) factory.generatePrivate(privKeySpec);
		}

		// import the key entry.
		ks.setKeyEntry("rsa-key-2048", priKey, passphrase, trustedCerts);
		// create SSL context
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(ks, passphrase);
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(ts);
		SSLContext sslCtx = SSLContext.getInstance("TLSv1");
		sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		return sslCtx;
	}

	public static Certificate[] readCertificates(String contents) throws CertificateException, IOException {
		CertificateFactory fact = CertificateFactory.getInstance("X.509");
		InputStream is = new ByteArrayInputStream(contents.getBytes());
		X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
		return new Certificate[] { cer };
	}
}
