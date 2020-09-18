package test.channel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import test.TcpProxyTest;
import tlschannel.async.AsynchronousTlsChannel;
import tlschannel.async.AsynchronousTlsChannelGroup;

/**
 * Server asynchronous example. Accepts any number of connections and echos
 * bytes sent by the clients into standard output.
 *
 * <p>
 * To test, use: <code> openssl s_client -connect localhost:10000 </code>
 *
 * <p>
 * This class exemplifies the use of {@link AsynchronousTlsChannel}. It
 * implements a blocking select loop, that processes new connections
 * asynchronously using asynchronous channel and callbacks, hiding the
 * complexity of a select loop.
 */
public class AsynchronousChannelServer {
	private static final Class<?> THIS_CLASS = new Object() {
	}.getClass().getEnclosingClass();
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(THIS_CLASS);
	private static final int BYTE_BUFFER_CAPACITY = 10_000;
	private Map<SocketAddress, AsynchronousSocketChannel> backendSocketChannel = new ConcurrentHashMap<>();

	public static void main(String[] args) throws IOException, GeneralSecurityException {
		// initialize the SSLContext, a configuration holder, reusable object
		SSLContext sslContext = TcpProxyTest.createSSLContext();
		AsynchronousTlsChannelGroup channelGroup = new AsynchronousTlsChannelGroup();
		// connect server socket channel and register it in the selector
		try (ServerSocketChannel serverSocket = ServerSocketChannel.open()) {
			InetSocketAddress address = new InetSocketAddress(8282);
			serverSocket.socket().bind(address);
			// accept raw connections normally
			System.out.println(String.format("Waiting for connection [%s]...", address));
			while (!Thread.currentThread().isInterrupted()) {
				SocketChannel rawChannel = serverSocket.accept();
				rawChannel.configureBlocking(false);
				// build asynchronous channel, based in the TLS channel and associated with the
				// global
				// group.
				AsynchronousTlsChannelExt asyncTlsChannel = new AsynchronousTlsChannelExt(channelGroup, rawChannel,
						null, v -> Optional.of(sslContext));
				asyncTlsChannel.getTlsChannel().setSslHandshakeTimeout(Duration.ofSeconds(1));
				frontEndRead(asyncTlsChannel);
			}
		}
		System.exit(0);
	}

	private static void frontEndRead(AsynchronousTlsChannelExt asyncTlsChannel) {
		ByteBuffer buffer = ByteBuffer.allocate(BYTE_BUFFER_CAPACITY);
		asyncTlsChannel.read(buffer, null, new CompletionHandler<Integer, Object>() {

			private final AtomicReference<AsynchronousSocketChannel> backendClientRef = new AtomicReference<>();

			@Override
			public void completed(Integer result, Object attachment) {
				try {
					completedThrowing(result, attachment);
				} catch (Throwable t) {
					TunnelUtils.closeAndLogOnError("frontend completion error", t, asyncTlsChannel,
							backendClientRef.get());
				}
			}

			protected void completedThrowing(Integer result, Object attachment) throws IOException {
				if (result == -1) {
					TunnelUtils.closeQuietly(asyncTlsChannel, backendClientRef.get());
					return;
				}
				if (backendClientRef.get() == null)
					synchronized (backendClientRef) {
						if (backendClientRef.get() == null) {
							try {
								backendClientRef.set(createBackendClient(asyncTlsChannel, () -> {
									this.completed(result, attachment);
								}));
							} catch (Throwable t) {
								failed(t, attachment);
							}
							return;
						}
					}
				buffer.flip();
				CompletionHandler<Integer, Object> readHandler = this;
				backendClientRef.get().write(buffer, attachment, new CompletionHandler<Integer, Object>() {

					@Override
					public void completed(Integer result, Object attachment) {
						buffer.compact();
						asyncTlsChannel.read(buffer, null, readHandler);
					}

					@Override
					public void failed(Throwable exc, Object attachment) {
						TunnelUtils.closeAndLogOnError("frontend write error", exc, asyncTlsChannel,
								backendClientRef.get());
					}
				});

			}

			@Override
			public void failed(Throwable exc, Object attachment) {
				if (TunnelUtils.isCertificateUnknownError(exc))
					return;
				TunnelUtils.closeAndLogOnError("frontend read error", exc, asyncTlsChannel, backendClientRef.get());
			}
		});
	}

	protected static AsynchronousSocketChannel createBackendClient(AsynchronousTlsChannelExt asyncTlsChannel,
			Runnable connectCompleteCallback) throws IOException {
		SocketAddress hostAddress = getSocketAddress(asyncTlsChannel);
		if (hostAddress == null)
			throw new IOException(TunnelUtils.formatSummary("backend server discovery failed.",
					TunnelUtils.getSummary(asyncTlsChannel)));
		AsynchronousSocketChannel client = AsynchronousSocketChannel.open();
		ByteBuffer buffer = ByteBuffer.allocate(BYTE_BUFFER_CAPACITY);
		var readHandler = new CompletionHandler<Integer, Object>() {

			@Override
			public void completed(Integer result, Object attachment) {
				if (result == -1) {
					TunnelUtils.closeQuietly(client, asyncTlsChannel);
					return;
				}
				buffer.flip();
				CompletionHandler<Integer, Object> readHandler = this;
				asyncTlsChannel.write(buffer, attachment, new CompletionHandler<Integer, Object>() {

					@Override
					public void completed(Integer result, Object attachment) {
						buffer.compact();
						// repeat
						client.read(buffer, null, readHandler);
					}

					@Override
					public void failed(Throwable exc, Object attachment) {
						TunnelUtils.closeAndLogOnError("backend write error", exc, client, asyncTlsChannel);
					}
				});
			}

			@Override
			public void failed(Throwable exc, Object attachment) {
				TunnelUtils.closeAndLogOnError("backend read error", exc, client, asyncTlsChannel);

			}
		};
		client.connect(hostAddress, null, new CompletionHandler<Void, Object>() {
			@Override
			public void completed(Void result, Object attachment) {
				client.read(buffer, null, readHandler);
				connectCompleteCallback.run();
			}

			@Override
			public void failed(Throwable exc, Object attachment) {
				TunnelUtils.closeAndLogOnError("backend connect error", exc, client, asyncTlsChannel);
			}
		});
		return client;
	}

	private static SocketAddress getSocketAddress(AsynchronousTlsChannelExt asyncTlsChannel) {
		var sniServerName = asyncTlsChannel.getTlsChannel().getSniServerName();
		var serverName = TunnelUtils.getSNIServerNameValue(sniServerName);
		if (serverName == null)
			return null;
		System.out.println(serverName);
		return new InetSocketAddress("localhost", 8181);
	}

}