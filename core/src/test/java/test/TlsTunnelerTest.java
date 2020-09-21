package test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.GeneralSecurityException;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;

import com.lfp.tls.chanel.ext.core.TlsTunneler;

public class TlsTunnelerTest {

	public static void main(String[] args)
			throws IOException, GeneralSecurityException, InterruptedException, ExecutionException {
		var sslContext = TestServices.createSSLContext();
		var tunneler = new TlsTunneler() {

			@Override
			protected Optional<SSLContext> getSSLContext(Optional<SNIServerName> sniServerNameOp) {
				return Optional.of(sslContext);
			}

			@Override
			protected SocketAddress getBackEndSocketAddress(Optional<String> sniServerName) {
				if (sniServerName.filter(v -> v.startsWith("echo")).isPresent())
					return new InetSocketAddress("52.20.16.20", 30000);
				return new InetSocketAddress("localhost", 8181);
			}
		};
		var tunnel1 = tunneler.start(new InetSocketAddress(8282));
		//var tunnel2 = tunneler.start(new InetSocketAddress(8282));
		new Thread(() -> {
			while (true) {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					throw (((Object) e) instanceof java.lang.RuntimeException)
							? java.lang.RuntimeException.class.cast(e)
							: new RuntimeException(e);
				}
				System.out.println(tunnel1.getReadCount() + " - " + tunnel1.getWriteCount());
			}
		}).start();
		Thread.currentThread().join();
	}
}
