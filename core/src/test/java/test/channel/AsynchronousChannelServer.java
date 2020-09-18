package test.channel;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;

import com.lfp.tls.proxy.core.SessionInitCallbackLFP;

import test.TcpProxyTest;
import tlschannel.ServerTlsChannel;
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
	private static final Charset utf8 = StandardCharsets.UTF_8;

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

				// instantiate TlsChannel
				ServerTlsChannelExt tlsChannel = new ServerTlsChannelExt(rawChannel);
				tlsChannel.addSniSslContextFactory(v -> Optional.of(sslContext));
				tlsChannel.setSslHandshakeTimeout(Duration.ofSeconds(2), true);
				// tlsChannel = builder.build();

				// build asynchronous channel, based in the TLS channel and associated with the
				// global
				// group.
				AsynchronousTlsChannel asyncTlsChannel = new AsynchronousTlsChannel(channelGroup, tlsChannel,
						rawChannel);

				// write to stdout all data sent by the client
				ByteBuffer res = ByteBuffer.allocate(10000);

				asyncTlsChannel.read(res, null, new CompletionHandler<Integer, Object>() {

					private final AtomicReference<AsynchronousSocketChannel> backendClientRef = new AtomicReference<>();

					@Override
					public void completed(Integer result, Object attachment) {
						try {
							completedInternal(result, attachment);
						} catch (Throwable t) {
							failed(t, attachment);
						}
					}

					protected void completedInternal(Integer result, Object attachment) throws IOException {
						if (result != -1) {
							boolean handled = false;
							if (backendClientRef.get() == null)
								synchronized (backendClientRef) {
									if (backendClientRef.get() == null)
										try {
											backendClientRef.set(createBackendClient(asyncTlsChannel, () -> {
												this.completed(result, attachment);
											}));
											handled = true;
										} catch (IOException e) {
											failed(e, attachment);
										}
								}
							if (handled)
								return;
							res.flip();
							CompletionHandler<Integer, Object> readHandler = this;
							backendClientRef.get().write(res, attachment, new CompletionHandler<Integer, Object>() {

								@Override
								public void completed(Integer result, Object attachment) {
									res.compact();
									// repeat
									asyncTlsChannel.read(res, null, readHandler);
								}

								@Override
								public void failed(Throwable exc, Object attachment) {
									failed(exc, attachment);
								}
							});
						} else {
							tlsChannel.validateSslSession();
							closeQuietly(asyncTlsChannel);
							closeQuietly(backendClientRef.get());
						}
					}

					@Override
					public void failed(Throwable exc, Object attachment) {
						if (exc instanceof SSLHandshakeException) {
							String msg = Optional.ofNullable(exc.getMessage()).map(String::toLowerCase).orElse("");
							if (msg.contains("Received fatal alert: certificate_unknown".toLowerCase()))
								return;
						}
						closeQuietly(tlsChannel);
						closeQuietly(asyncTlsChannel);
						closeQuietly(backendClientRef.get());
						logger.warn("server error", exc);
					}
				});
			}

		}
		System.exit(0);
	}

	protected static AsynchronousSocketChannel createBackendClient(AsynchronousTlsChannel asyncTlsChannel,
			Runnable connectCompleteCallback) throws IOException {
		AsynchronousSocketChannel client = AsynchronousSocketChannel.open();
		InetSocketAddress hostAddress = new InetSocketAddress("localhost", 8181);
		ByteBuffer res = ByteBuffer.allocate(10000);
		var readHandler = new CompletionHandler<Integer, Object>() {

			@Override
			public void completed(Integer result, Object attachment) {
				if (result != -1) {
					res.flip();
					CompletionHandler<Integer, Object> readHandler = this;
					asyncTlsChannel.write(res, attachment, new CompletionHandler<Integer, Object>() {

						@Override
						public void completed(Integer result, Object attachment) {
							res.compact();
							// repeat
							client.read(res, null, readHandler);
						}

						@Override
						public void failed(Throwable exc, Object attachment) {
							failed(exc, attachment);
						}
					});
				} else {
					closeQuietly(client);
					closeQuietly(asyncTlsChannel);
				}

			}

			@Override
			public void failed(Throwable exc, Object attachment) {
				closeQuietly(client);
				closeQuietly(asyncTlsChannel);
				logger.warn("backend read error", exc);

			}
		};
		client.connect(hostAddress, null, new CompletionHandler<Void, Object>() {
			@Override
			public void completed(Void result, Object attachment) {
				client.read(res, null, readHandler);
				connectCompleteCallback.run();
			}

			@Override
			public void failed(Throwable exc, Object attachment) {
				closeQuietly(client);
				closeQuietly(asyncTlsChannel);
				logger.warn("backend connect error", exc);
			}
		});
		return client;
	}

	private static void closeQuietly(Closeable closeable) {
		if (closeable == null)
			return;
		try {
			closeable.close();
		} catch (IOException e) {
			// suppress
		}

	}
}