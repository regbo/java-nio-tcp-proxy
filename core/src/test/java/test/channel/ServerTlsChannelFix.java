package test.channel;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import com.lfp.joe.utils.Utils;
import com.lfp.tls.proxy.core.SessionInitCallbackLFP;

import tlschannel.ServerTlsChannel;
import tlschannel.TlsChannel;
import tlschannel.TrackingAllocator;

public class ServerTlsChannelFix implements TlsChannel {
	private final ServerTlsChannel delegate;
	private final Duration sshHandshakeTimeout;
	private boolean sshHandshakeTimedout;
	private CompletableFuture<Void> sshHandshakeTimeoutFuture;

	public ServerTlsChannelFix(ServerTlsChannel serverTlsChannel, Duration sshHandshakeTimeout) {
		this.delegate = Objects.requireNonNull(serverTlsChannel);
		getSessionInitCallback();
		this.sshHandshakeTimeout = Objects.requireNonNull(sshHandshakeTimeout);
	}

	public boolean isSshHandshakeTimedout() {
		return sshHandshakeTimedout;
	}

	@Override
	public SessionInitCallbackLFP getSessionInitCallback() {
		return Utils.Types.tryCast(this.delegate.getSessionInitCallback(), SessionInitCallbackLFP.class).orElseThrow();
	}

	@Override
	public long read(ByteBuffer[] dstBuffers, int offset, int length) throws IOException {
		return tryRead(() -> delegate.read(dstBuffers, offset, length));
	}

	@Override
	public long read(ByteBuffer[] dstBuffers) throws IOException {
		return tryRead(() -> delegate.read(dstBuffers));
	}

	@Override
	public int read(ByteBuffer dstBuffer) throws IOException {
		return tryRead(() -> delegate.read(dstBuffer));
	}

	protected <X> X tryRead(Callable<X> callable) throws IOException {
		if (sshHandshakeTimeoutFuture == null && getSessionInitCallback().getSSLSession().isEmpty())
			synchronized (this) {
				if (sshHandshakeTimeoutFuture == null && getSessionInitCallback().getSSLSession().isEmpty())
					this.sshHandshakeTimeoutFuture = CompletableFuture.runAsync(() -> {
						if (getSessionInitCallback().getSSLSession().isPresent())
							return;
						sshHandshakeTimedout = true;
						try {
							this.close();
						} catch (IOException e) {
							throw (((Object) e) instanceof java.lang.RuntimeException)
									? java.lang.RuntimeException.class.cast(e)
									: new RuntimeException(e);
						}
					}, CompletableFuture.delayedExecutor(sshHandshakeTimeout.toMillis(), TimeUnit.MILLISECONDS));
			}
		try {
			return callable.call();
		} catch (Exception e) {
			if (e instanceof IOException)
				throw (IOException) e;
			throw (((Object) e) instanceof java.lang.RuntimeException) ? java.lang.RuntimeException.class.cast(e)
					: new RuntimeException(e);
		}
	}

	public SSLContext getSslContext() {
		return delegate.getSslContext();
	}

	@Override
	public int hashCode() {
		return delegate.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return delegate.equals(obj);
	}

	@Override
	public ByteChannel getUnderlying() {
		return delegate.getUnderlying();
	}

	@Override
	public SSLEngine getSslEngine() {
		return delegate.getSslEngine();
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

}
