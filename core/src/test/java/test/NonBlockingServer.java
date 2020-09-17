package test;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import javax.net.ssl.SSLContext;

import com.lfp.joe.threads.Threads;
import com.lfp.joe.utils.Utils;
import com.lfp.joe.utils.function.Throwing.ThrowingConsumer;
import com.lfp.tls.proxy.core.SessionInitCallbackLFP;

import tlschannel.NeedsReadException;
import tlschannel.NeedsWriteException;
import tlschannel.ServerTlsChannel;
import tlschannel.TlsChannel;

/**
 * Server non-blocking example. Accepts any number of connections and echos
 * bytes sent by the clients into standard output.
 *
 * <p>
 * To test, use: <code> openssl s_client -connect localhost:10000 </code>
 *
 * <p>
 * This example is similar to the canonical selector loop, except for:
 *
 * <ul>
 * <li>When a connection arrives, the newly-created channel is wrapped in a
 * TlsChannel: all IO is done using the TlsChannel, but the raw channel is
 * registered in the selector.
 * <li>IO operations are surrounded in a try-catch block that traps
 * {@link NeedsWriteException} and {@link NeedsReadException} and enables the
 * appropriate operation for the corresponding key.
 * </ul>
 */
public class NonBlockingServer {
	private static final Class<?> THIS_CLASS = new Object() {
	}.getClass().getEnclosingClass();
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(THIS_CLASS);
	private static final int BYTE_BUFFER_SIZE = 8192;

	public static void main(String[] args) throws IOException, GeneralSecurityException, InterruptedException {
		// connect server socket channel and register it in the selector
		try (ServerSocketChannel serverSocket = ServerSocketChannel.open()) {
			serverSocket.socket().bind(new InetSocketAddress(8282));
			serverSocket.configureBlocking(false);
			SSLContext sslContext = TcpProxyTest.createSSLContext();
			int workers = Utils.Machine.logicalProcessorCount();
			for (int i = 0; i < workers; i++) {
				var serverSelector = Selector.open();
				var forwardSelector = Selector.open();
				var selectorProcessor = SelectorProcessor
						.createLogging((nil, key) -> process(sslContext, serverSelector, forwardSelector, key));
				selectorProcessor.start(Threads.CentralPool.unlimitedPool(), () -> {
					serverSocket.register(serverSelector, SelectionKey.OP_ACCEPT);
					return Arrays.asList(serverSelector, forwardSelector);
				});
			}
			System.out.println("workers:" + workers);
			Thread.currentThread().join();
		}

	}

	private static void process(SSLContext sslContext, Selector serverSelector, Selector forwardSelector,
			SelectionKey key) throws IOException {
		if (key.attachment() != null) {
			var kc = KeyContext.get(key);
			if (kc.getTlsChannel() == null)
				System.out.println(kc);
		}
		if (key.selector() == serverSelector)
			processServer(sslContext, forwardSelector, key);
		else
			processForward(serverSelector, key);
	}

	private static void processServer(SSLContext sslContext, Selector forwardSelector, SelectionKey key)
			throws IOException {
		if (key.isValid() && key.isAcceptable()) {
			ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();
			SocketChannel rawChannel = serverChannel.accept();
			initializeChannel(sslContext, key, rawChannel);
		} else if (key.isValid() && (key.isReadable() || key.isWritable())) {
			KeyContext.requirePresent(key);
			if (handshakeForced(key))
				return;
			if (forwardChannelLookup(forwardSelector, key))
				return;
			var keyContext = KeyContext.get(key);
			System.out.println(keyContext.getSNIServerName().orElse(null));
			accessTlsChannel(key, tlsChannel -> {
				SocketChannel forwardChannel = keyContext.getForwardChannel();
				ByteBuffer bb = ByteBuffer.allocateDirect(BYTE_BUFFER_SIZE);
				int read = tlsChannel.read(bb);
				if (read > 0) {
					bb.flip();
					forwardChannel.write(bb);
					key.channel().register(key.selector(), SelectionKey.OP_READ, keyContext);
				}
				if (read < 0)
					closeQuietly(forwardChannel);
			});
		} else {
			throw new IllegalStateException("unrecognized key options:" + key.interestOps());
		}
	}

	private static void processForward(Selector serverSelector, SelectionKey key) throws IOException {
		if (key.isValid() && (key.isReadable() || key.isWritable())) {
			KeyContext.requirePresent(key);
			var forwardChannel = (SocketChannel) key.channel();
			ByteBuffer bb = ByteBuffer.allocateDirect(BYTE_BUFFER_SIZE);
			int read = forwardChannel.read(bb);
			if (read > 0) {
				bb.flip();
				accessTlsChannel(key, tlsChanel -> tlsChanel.write(bb));
			}
			if (read < 0) {
				var keyContext = KeyContext.get(key);
				var tlsc = keyContext.getTlsChannel();
				if (tlsc != null) {
					closeQuietly(tlsc);
					closeQuietly(tlsc.getUnderlying());
				}
			}
		} else {
			throw new IllegalStateException("unrecognized key options:" + key.interestOps());
		}

	}

	private static boolean forwardChannelLookup(Selector forwardSelector, SelectionKey key) throws IOException {
		if (KeyContext.get(key).getForwardChannel() != null)
			return false;
		SocketChannel forwardTo = SocketChannel.open(new InetSocketAddress("localhost", 8181));
		forwardTo.configureBlocking(false);
		forwardTo.finishConnect();
		var kc = KeyContext.access(key, v -> v.toBuilder().forwardChannel(forwardTo).build());
		forwardTo.register(forwardSelector, SelectionKey.OP_READ, kc);
		key.channel().register(key.selector(), SelectionKey.OP_READ, kc);
		return true;
	}

	private static boolean handshakeForced(SelectionKey key) throws IOException {
		var kc = KeyContext.get(key);
		if (kc.getSNIServerName().isPresent())
			return false;
		accessTlsChannel(key, tlsChannel -> tlsChannel.handshake());
		key.channel().register(key.selector(), SelectionKey.OP_READ, kc);
		return true;
	}

	private static void accessTlsChannel(SelectionKey key, ThrowingConsumer<TlsChannel, IOException> accessor)
			throws IOException {
		Objects.requireNonNull(key);
		Objects.requireNonNull(accessor);
		var tlsChannel = Objects.requireNonNull(KeyContext.get(key).getTlsChannel());
		try {
			accessor.accept(tlsChannel);
		} catch (NeedsReadException e) {
			key.interestOps(SelectionKey.OP_READ); // overwrites previous value
		} catch (NeedsWriteException e) {
			key.interestOps(SelectionKey.OP_WRITE); // overwrites previous value
		} catch (Throwable t) {
			tlsChannel.close();
			throw t;
		}
	}

	private static void initializeChannel(SSLContext sslContext, SelectionKey key, SocketChannel rawChannel)
			throws IOException {
		if (rawChannel == null)
			return;
		rawChannel.configureBlocking(false);
		{// configure ssl
			SessionInitCallbackLFP sessionInitCallback = new SessionInitCallbackLFP();
			TlsChannel tlsChannel = ServerTlsChannel.newBuilder(rawChannel, sniNameOp -> {
				sessionInitCallback.accept(sniNameOp.orElse(null));
				return Optional.of(sslContext);
			}).withSessionInitCallback(sessionInitCallback).build();
			KeyContext.access(key, kc -> kc.toBuilder().tlsChannel(tlsChannel).build());
		}
		{// kick can down the road
			SelectionKey newKey = rawChannel.register(key.selector(), SelectionKey.OP_READ);
			KeyContext.copy(key, newKey);
		}
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
