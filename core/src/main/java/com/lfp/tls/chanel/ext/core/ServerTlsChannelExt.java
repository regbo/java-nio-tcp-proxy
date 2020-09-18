package com.lfp.tls.chanel.ext.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.net.ssl.SNIServerName;
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

	private final ReadWriteLock sniSslContextFactoriesLock = new ReentrantReadWriteLock();
	private final List<SniSslContextFactory> sniSslContextFactories = new ArrayList<>();
	private final CompletableFuture<SSLSession> sslSessionFuture = new CompletableFuture<>();
	private final AtomicReference<CompletableFuture<Void>> sslHandshakeTimeoutFutureRef = new AtomicReference<>();
	private final ServerTlsChannel delegate;
	private long readCount;
	private long writeCount;
	private Duration sslHandshakeTimeout;
	private boolean disableSslHandshakeTimeoutLogging;
	private boolean fixedSSLContext;
	private SNIServerName sniServerName;

	public ServerTlsChannelExt(ByteChannel underlying, Consumer<ServerTlsChannel.Builder> builderModifier,
			SniSslContextFactory... sniSslContextFactories) {
		this(underlying, builderModifier, (SSLContext) null);
		if (sniSslContextFactories != null)
			for (var sniSslContextFactory : sniSslContextFactories)
				this.addSniSslContextFactory(sniSslContextFactory);
	}

	@SuppressWarnings("unchecked")
	public ServerTlsChannelExt(ByteChannel underlying, Consumer<ServerTlsChannel.Builder> builderModifier,
			SSLContext fixedSSLContext) {
		ServerTlsChannel.Builder delegateBuilder;
		if (fixedSSLContext == null) {
			delegateBuilder = ServerTlsChannel.newBuilder(underlying, sniServerNameOp -> {
				sniSslContextFactoriesLock.readLock().lock();
				this.sniServerName = sniServerNameOp.orElse(null);
				try {
					for (var fact : sniSslContextFactories) {
						var sslContextOp = fact.getSslContext(sniServerNameOp);
						if (sslContextOp != null && sslContextOp.isPresent())
							return sslContextOp;
					}
				} finally {
					sniSslContextFactoriesLock.readLock().unlock();
				}
				return Optional.empty();
			});
		} else {
			delegateBuilder = ServerTlsChannel.newBuilder(underlying, fixedSSLContext);
			this.fixedSSLContext = true;
		}
		if (builderModifier != null)
			builderModifier.accept(delegateBuilder);
		this.delegate = delegateBuilder.build();
		TunnelUtils.uncheckedFieldAccess(this.delegate, "sessionInitCallback", Consumer.class, (getter, setter) -> {
			Consumer<SSLSession> currentSessionInitCallback = getter.get();
			Consumer<SSLSession> sessionInitCallback = ssls -> {
				getSslSessionFuture().complete(ssls);
				if (currentSessionInitCallback != null)
					currentSessionInitCallback.accept(ssls);
			};
			setter.accept(sessionInitCallback);
			return null;
		});

	}

	public CompletableFuture<SSLSession> getSslSessionFuture() {
		if (!sslSessionFuture.isDone()) {
			var ssls = Optional.ofNullable(this.delegate.getSslEngine()).map(v -> v.getSession()).orElse(null);
			if (ssls != null)
				sslSessionFuture.complete(ssls);
		}
		return sslSessionFuture;
	}

	public boolean addSniSslContextFactory(SniSslContextFactory sniSslContextFactory) {
		if (sniSslContextFactory == null)
			return false;
		if (this.fixedSSLContext)
			return false;
		sniSslContextFactoriesLock.writeLock().lock();
		try {
			if (sniSslContextFactories.contains(sniSslContextFactory))
				return false;
			return sniSslContextFactories.add(sniSslContextFactory);
		} finally {
			sniSslContextFactoriesLock.writeLock().unlock();
		}
	}

	public boolean removeSniSslContextFactory(SniSslContextFactory sniSslContextFactory) {
		if (sniSslContextFactory == null)
			return false;
		sniSslContextFactoriesLock.writeLock().lock();
		try {
			return sniSslContextFactories.remove(sniSslContextFactory);
		} finally {
			sniSslContextFactoriesLock.writeLock().unlock();
		}
	}

	public SSLContext getSslContext() {
		return delegate.getSslContext();
	}

	public void setSslHandshakeTimeout(Duration sslHandshakeTimeout) {
		this.setSslHandshakeTimeout(sslHandshakeTimeout, false);
	}

	public void setSslHandshakeTimeout(Duration sslHandshakeTimeout, boolean disableSslHandshakeTimeoutLogging) {
		this.sslHandshakeTimeout = sslHandshakeTimeout;
		this.disableSslHandshakeTimeoutLogging = disableSslHandshakeTimeoutLogging;
	}

	private <N extends Number> N recordRead(N count) {
		var value = count.longValue();
		if (value >= 0)
			readCount += value;
		return count;
	}

	@Override
	public long read(ByteBuffer[] dstBuffers, int offset, int length) throws IOException {
		return handleRead(() -> recordRead(delegate.read(dstBuffers, offset, length)));
	}

	@Override
	public long read(ByteBuffer[] dstBuffers) throws IOException {
		return handleRead(() -> recordRead(delegate.read(dstBuffers)));
	}

	@Override
	public int read(ByteBuffer dstBuffer) throws IOException {
		return handleRead(() -> recordRead(delegate.read(dstBuffer)));
	}

	@SuppressWarnings("unchecked")
	protected <X extends Number> X handleRead(Callable<X> readTask) throws IOException {
		Objects.requireNonNull(readTask);
		Exception error = null;
		try {
			return readTask.call();
		} catch (Exception e) {
			error = e;
		}
		if (!(error instanceof NeedsReadException))
			return TunnelUtils.tryThrowAs(error, IOException.class);
		NeedsReadException needsReadException = (NeedsReadException) error;
		if (sslHandshakeTimeout == null)
			throw needsReadException;
		if (getSslSessionFuture().isDone())
			throw needsReadException;
		if (sslHandshakeTimeoutFutureRef.get() == null) {
			synchronized (sslHandshakeTimeoutFutureRef) {
				if (sslHandshakeTimeoutFutureRef.get() == null) {
					var executor = CompletableFuture.delayedExecutor(this.sslHandshakeTimeout.toMillis(),
							TimeUnit.MILLISECONDS);
					Date startedAt = new Date();
					var future = CompletableFuture.runAsync(() -> closeIfNotReady(startedAt), executor);
					this.getSslSessionFuture().whenComplete((v, t) -> future.cancel(true));
					sslHandshakeTimeoutFutureRef.set(future);
				}
			}
		}
		throw needsReadException;
	}

	protected void closeIfNotReady(Date startedAt) {
		if (getSslSessionFuture().isDone())
			return;
		Map<String, Object> logData = TunnelUtils.getSummary(this);
		logData.put("elapsedMillis", System.currentTimeMillis() - startedAt.getTime());
		logData.put("timeoutMillis", sslHandshakeTimeout.toMillis());
		String msg = TunnelUtils.formatSummary("ssl handshake timeout.", logData);
		var error = new SSLHandshakeException(msg);
		var completeExceptionally = getSslSessionFuture().completeExceptionally(error);
		if (!completeExceptionally)
			return;
		try {
			this.close();
		} catch (IOException e) {
			// suppress
		}
		if (!disableSslHandshakeTimeoutLogging)
			logger.error(msg, error);
	}

	private <N extends Number> N recordWrite(N count) {
		var value = count.longValue();
		if (value >= 0)
			writeCount += value;
		return count;
	}

	@Override
	public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
		return recordWrite(delegate.write(srcs, offset, length));
	}

	@Override
	public long write(ByteBuffer[] srcs) throws IOException {
		return recordWrite(delegate.write(srcs));
	}

	public long getReadCount() {
		return readCount;
	}

	public long getWriteCount() {
		return writeCount;
	}

	public SNIServerName getSniServerName() {
		return sniServerName;
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
