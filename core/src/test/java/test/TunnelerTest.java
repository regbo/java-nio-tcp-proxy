package test;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.AsynchronousByteChannel;

import com.lfp.tls.chanel.ext.core.Tunneler;

public class TunnelerTest {

	public static void main(String[] args) throws InterruptedException {
		Tunneler tunneler = new Tunneler() {

			@Override
			protected SocketAddress getBackEndSocketAddress(AsynchronousByteChannel byteChannel) {
				return new InetSocketAddress("localhost", 8181);
			}
		};
		var tunnel = tunneler.start(new InetSocketAddress(8282));
		tunnel.getReadCounter().addListener(evt -> {
			System.out.println("read:" + evt.getBytesTotal());
		});
		tunnel.getWriteCounter().addListener(evt -> {
			System.out.println("write:" + evt.getBytesTotal());
		});
		System.out.println("started");
		Thread.currentThread().join();
	}

}
