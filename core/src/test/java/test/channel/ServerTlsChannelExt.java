package test.channel;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;

import tlschannel.NeedsReadException;
import tlschannel.ServerTlsChannel;
import tlschannel.SniSslContextFactory;
import tlschannel.TlsChannel;
import tlschannel.TrackingAllocator;

public class ServerTlsChannelExt implements TlsChannel {
	private static final Class<?> THIS_CLASS = new Object() {
	}.getClass().getEnclosingClass();
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(THIS_CLASS);
	private static final byte[] CLOSE_BARR = new byte[] { -1 };
	private static final ByteBuffer[] CLOSE_BUFFS = new ByteBuffer[0];
	private final ReadWriteLock rwLock = new ReentrantReadWriteLock();
	private final List<SniSslContextFactory> sniSslContextFactories = new ArrayList<>();
	private final CompletableFuture<SSLSession> sslSessionFuture = new CompletableFuture<>();
	private final AtomicReference<CompletableFuture<Void>> sslHandshakeTimeoutFutureRef = new AtomicReference<>();
	private final ServerTlsChannel delegate;
	private Duration sslHandshakeTimeout;
	private boolean sslHandshakeTimeoutLogging;

	public ServerTlsChannelExt(ByteChannel underlying) {
		ServerTlsChannel.Builder delegateBuilder = ServerTlsChannel.newBuilder(underlying, sniServerNameOp -> {
			rwLock.readLock().lock();
			try {
				for (var fact : sniSslContextFactories) {
					var sslContextOp = fact.getSslContext(sniServerNameOp);
					if (sslContextOp != null && sslContextOp.isPresent())
						return sslContextOp;
				}
			} finally {
				rwLock.readLock().unlock();
			}
			return Optional.empty();
		});
		delegateBuilder = delegateBuilder.withSessionInitCallback(sslSessionFuture::complete);
		this.delegate = delegateBuilder.build();
	}

	public CompletableFuture<SSLSession> getSslSessionFuture() {
		return sslSessionFuture;
	}

	public boolean addSniSslContextFactory(SniSslContextFactory sniSslContextFactory) {
		if (sniSslContextFactory == null)
			return false;
		rwLock.writeLock().lock();
		try {
			if (sniSslContextFactories.contains(sniSslContextFactory))
				return false;
			return sniSslContextFactories.add(sniSslContextFactory);
		} finally {
			rwLock.writeLock().unlock();
		}
	}

	public boolean removeSniSslContextFactory(SniSslContextFactory sniSslContextFactory) {
		if (sniSslContextFactory == null)
			return false;
		rwLock.writeLock().lock();
		try {
			return sniSslContextFactories.remove(sniSslContextFactory);
		} finally {
			rwLock.writeLock().unlock();
		}
	}

	public SSLContext getSslContext() {
		return delegate.getSslContext();
	}

	public void validateSslSession() throws IOException {
		Throwable error = null;
		try {
			var session = this.getSslSessionFuture().getNow(null);
			if (session != null)
				return;
		} catch (Throwable t) {
			error = t;
		}
		while ((error instanceof CompletionException || error instanceof ExecutionException)
				&& error.getCause() != null)
			error = error.getCause();
		if (error instanceof IOException)
			throw (IOException) error;
		String msg = "ssl session validation failed";
		if (error != null)
			throw new IOException(msg, error);
		throw new IOException(msg);

	}

	@Override
	public long read(ByteBuffer[] dstBuffers, int offset, int length) throws IOException {
		return handleRead(() -> delegate.read(dstBuffers, offset, length));
	}

	@Override
	public long read(ByteBuffer[] dstBuffers) throws IOException {
		return handleRead(() -> delegate.read(dstBuffers));
	}

	@Override
	public int read(ByteBuffer dstBuffer) throws IOException {
		return handleRead(() -> delegate.read(dstBuffer));
	}

	protected <X> X handleRead(ReadTask<X> readTask) throws IOException {
		Objects.requireNonNull(readTask);
		IOException error = null;
		try {
			return readTask.read();
		} catch (IOException e) {
			error = e;
		}
		if (!(error instanceof NeedsReadException))
			throw error;
		if (sslHandshakeTimeout == null)
			throw error;
		if (sslSessionFuture.isDone())
			throw error;
		if (sslHandshakeTimeoutFutureRef.get() == null) {
			synchronized (sslHandshakeTimeoutFutureRef) {
				if (sslHandshakeTimeoutFutureRef.get() == null) {
					var executor = CompletableFuture.delayedExecutor(this.sslHandshakeTimeout.toMillis(),
							TimeUnit.MILLISECONDS);
					Date startedAt = new Date();
					var future = CompletableFuture.runAsync(() -> closeIfNotReady(startedAt), executor);
					this.sslSessionFuture.whenComplete((v, t) -> future.cancel(true));
					sslHandshakeTimeoutFutureRef.set(future);
				}
			}
		}
		throw error;
	}

	protected void closeIfNotReady(Date startedAt) {
		if (sslSessionFuture.isDone())
			return;
		long elapsed = System.currentTimeMillis() - startedAt.getTime();
		String msg = String.format("ssl handshake timeout. elapsed:%s timeoutMillis:%s", elapsed,
				sslHandshakeTimeout.toMillis());
		var error = new SSLHandshakeException(msg);
		var completeExceptionally = sslSessionFuture.completeExceptionally(error);
		if (!completeExceptionally)
			return;
		try {
			this.close();
		} catch (IOException e) {
			// suppress
		}
		if (sslHandshakeTimeoutLogging)
			logger.error(msg, error);
	}

	public void setSslHandshakeTimeout(Duration sslHandshakeTimeout, boolean sslHandshakeTimeoutLogging) {
		this.sslHandshakeTimeout = sslHandshakeTimeout;
		this.sslHandshakeTimeoutLogging = sslHandshakeTimeoutLogging;
	}

	private static interface ReadTask<X> {

		public X read() throws IOException;
	}

	// delegates

	@Override
	public ByteChannel getUnderlying() {
		return delegate.getUnderlying();
	}

	@Override
	public SSLEngine getSslEngine() {
		return delegate.getSslEngine();
	}

	@Override
	public Consumer<SSLSession> getSessionInitCallback() {
		return delegate.getSessionInitCallback();
	}

	@Override
	public boolean getRunTasks() {
		return delegate.getRunTasks();
	}

	@Override
	public TrackingAllocator getPlainBufferAllocator() {
		return delegate.getPlainBufferAllocator();
	}

	@Override
	public TrackingAllocator getEncryptedBufferAllocator() {
		return delegate.getEncryptedBufferAllocator();
	}

	@Override
	public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
		return delegate.write(srcs, offset, length);
	}

	@Override
	public long write(ByteBuffer[] srcs) throws IOException {
		return delegate.write(srcs);
	}

	@Override
	public int write(ByteBuffer srcBuffer) throws IOException {
		return delegate.write(srcBuffer);
	}

	@Override
	public void renegotiate() throws IOException {
		delegate.renegotiate();
	}

	@Override
	public void handshake() throws IOException {
		delegate.handshake();
	}

	@Override
	public void close() throws IOException {
		delegate.close();
	}

	@Override
	public String toString() {
		return delegate.toString();
	}

	@Override
	public boolean isOpen() {
		return delegate.isOpen();
	}

	@Override
	public boolean shutdown() throws IOException {
		return delegate.shutdown();
	}

	@Override
	public boolean shutdownReceived() {
		return delegate.shutdownReceived();
	}

	@Override
	public boolean shutdownSent() {
		return delegate.shutdownSent();
	}

	@Override
	public int hashCode() {
		return delegate.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return delegate.equals(obj);
	}

}
