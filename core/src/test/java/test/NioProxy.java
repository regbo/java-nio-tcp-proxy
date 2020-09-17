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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import tlschannel.NeedsReadException;
import tlschannel.NeedsWriteException;
import tlschannel.ServerTlsChannel;
import tlschannel.TlsChannel;

public class NioProxy {
	private static final Class<?> THIS_CLASS = new Object() {
	}.getClass().getEnclosingClass();
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(THIS_CLASS);
	// mappa client remoto - server remoto
	private Map<SocketChannel, SocketChannel> proxy = new ConcurrentHashMap<>();
	private static final int BYTE_BUFFER_SIZE = 8192;
	private static final Executor EXECUTOR = Executors
			.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
	SSLContext sslContext;

	public void serve() throws IOException, GeneralSecurityException {
		sslContext = TcpProxyTest.createSSLContext();
		ServerSocketChannel sChannel = ServerSocketChannel.open();
		sChannel.configureBlocking(false);
		sChannel.socket().bind(new InetSocketAddress(8383));
		var serverSel = SyncedSelector.create(EXECUTOR);
		var remoteSel = SyncedSelector.create(EXECUTOR);
		serverSel.addProcessor(k -> server(serverSel, remoteSel, k));
		remoteSel.addProcessor(k -> remote(serverSel, remoteSel, k));
		serverSel.register(sChannel, SelectionKey.OP_ACCEPT);
		Arrays.asList(serverSel, remoteSel).forEach(v -> execute(v));
		System.out.println("registration complete");
	}

	private void remote(SyncedSelector serverSel, SyncedSelector remoteSel, SelectionKey key) {
		try {
			remoteInternal(remoteSel, remoteSel, key);
		} catch (IOException e) {
			throw (((Object) e) instanceof java.lang.RuntimeException) ? java.lang.RuntimeException.class.cast(e)
					: new RuntimeException(e);
		}

	}

	private void remoteInternal(SyncedSelector serverSel, SyncedSelector remoteSel, SelectionKey key) throws IOException {
		if (key.isValid() && key.isReadable()) { // leggo dal server remoto
			ByteBuffer bb = ByteBuffer.allocateDirect(BYTE_BUFFER_SIZE);
			SocketChannel forwardTo = (SocketChannel) key.channel();
			int read = forwardTo.read(bb);
			for (SocketChannel rawChannel : proxy.keySet()) {
				if (proxy.get(rawChannel).equals(forwardTo)) {
					TlsChannel tlsChannel = (TlsChannel) key.attachment();
					try {
						if (read < 0) { // il client si è disconnesso
							closeQuietly(forwardTo);
							closeQuietly(tlsChannel);
							proxy.remove(rawChannel);
						}
						if (read > 0) { // client manda dati
							bb.flip();
							tlsChannel.write(bb);
						}
					} catch (NeedsReadException e) {
						key.interestOps(SelectionKey.OP_READ); // overwrites previous value
					} catch (NeedsWriteException e) {
						key.interestOps(SelectionKey.OP_WRITE); // overwrites previous value
					}
				}
			}

		}
	}

	private void server(SyncedSelector serverSel, SyncedSelector remoteSel, SelectionKey key) {
		try {
			serverInternal(remoteSel, remoteSel, key);
		} catch (IOException e) {
			throw java.lang.RuntimeException.class.isAssignableFrom(e.getClass())
					? java.lang.RuntimeException.class.cast(e)
					: new java.lang.RuntimeException(e);
		}
	}

	private void serverInternal(SyncedSelector serverSel, SyncedSelector remoteSel, SelectionKey key) throws IOException {
		if (key.isAcceptable()) {
			// we have a new connection
			ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();

			// accept new connection
			SocketChannel rawChannel = serverChannel.accept();

			rawChannel.configureBlocking(false);

			TlsChannel tlsChannel = ServerTlsChannel.newBuilder(rawChannel, sslContext)
					.withSessionInitCallback(sslSession -> {
						System.out.println("ssl ready");
					}).build();
			SocketChannel forwardTo = SocketChannel.open(new InetSocketAddress("localhost", 8181));
			forwardTo.configureBlocking(false);
			forwardTo.finishConnect();
			proxy.put(rawChannel, forwardTo);
			remoteSel.register(forwardTo, SelectionKey.OP_READ, tlsChannel);
			serverSel.register(rawChannel, SelectionKey.OP_READ, tlsChannel);
			// Note that the raw channel is registered in the selector (and now the wrapped
			// ont),
			// the TlsChannel is put as an attachment. Additionally, the channel is
			// registered for
			// reading, because TLS connections are initiated by clients.

			// newKey.attach(tlsChannel);
			System.out.println(
					"Accept remote connection from " + rawChannel.socket().getRemoteSocketAddress().toString());
			// apro connessione verso sistema esterno

		}
		if (key.isWritable() || key.isReadable()) {
			// prendo il canale remoto
			SocketChannel rawChannel = (SocketChannel) key.channel();
			TlsChannel tlsChannel = (TlsChannel) key.attachment();
			try {
				SocketChannel forwardTo = proxy.get(key.channel());
				ByteBuffer bb = ByteBuffer.allocateDirect(BYTE_BUFFER_SIZE);
				int read = tlsChannel.read(bb);

				if (read < 0) { // il client si è disconnesso
					closeQuietly(forwardTo);
					closeQuietly(tlsChannel);
					closeQuietly(rawChannel);
					proxy.remove(rawChannel);
				}

				if (read > 0) { // client manda dati
					bb.flip();
					forwardTo.write(bb);
					serverSel.register(rawChannel, SelectionKey.OP_READ, tlsChannel);
				}
			} catch (NeedsReadException e) {
				key.interestOps(SelectionKey.OP_READ); // overwrites previous value
			} catch (NeedsWriteException e) {
				key.interestOps(SelectionKey.OP_WRITE); // overwrites previous value
			} catch (IOException e) {
				closeQuietly(tlsChannel);
				closeQuietly(rawChannel);
				proxy.remove(rawChannel);
				throw e;
			}
		}
	}

	private <X> CompletableFuture<X> execute(Callable<X> callable) {
		CompletableFuture<X> future = CompletableFuture.supplyAsync(() -> {
			try {
				return callable.call();
			} catch (Throwable t) {
				throw new CompletionException(t);
			}
		}, EXECUTOR);
		future.whenComplete((v, t) -> {
			if (t != null)
				logger.error("error", t);
		});
		return future;

	}

	private void closeQuietly(Closeable closeable) {
		if (closeable == null)
			return;
		try {
			closeable.close();
		} catch (IOException e) {
			// suppress
		}

	}

	/**
	 * @param args
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws GeneralSecurityException
	 */
	public static void main(String[] args) throws IOException, InterruptedException, GeneralSecurityException {
		new NioProxy().serve();
		Thread.currentThread().join();
	}

}