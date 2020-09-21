package com.lfp.tls.chanel.ext.core;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.CompletionHandler;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;

import tlschannel.async.AsynchronousTlsChannelGroup;

public abstract class TlsTunneler {
	private static final Class<?> THIS_CLASS = new Object() {
	}.getClass().getEnclosingClass();
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(THIS_CLASS);
	private static final int BYTE_BUFFER_CAPACITY = 10_000;
	private static final ExecutorService RUNNING_EXECUTOR_SERVICE = Executors.newCachedThreadPool();
	private final AsynchronousTlsChannelGroup channelGroup;

	public TlsTunneler() throws IOException {
		this(new AsynchronousTlsChannelGroup());
	}

	public TlsTunneler(AsynchronousTlsChannelGroup channelGroup) throws IOException {
		this.channelGroup = Objects.requireNonNull(channelGroup);
	}

	public Tunnel start(InetSocketAddress address) {
		Objects.requireNonNull(address);
		AtomicLong readCounter = new AtomicLong();
		AtomicLong writeCounter = new AtomicLong();
		Future<Void> future = RUNNING_EXECUTOR_SERVICE.submit(() -> {
			try {
				// connect server socket channel and register it in the selector
				try (ServerSocketChannel serverSocket = ServerSocketChannel.open()) {
					serverSocket.socket().bind(address);
					logger.info("listening for connections:{}", address);
					while (!Thread.currentThread().isInterrupted()) {
						SocketChannel rawChannel = serverSocket.accept();
						rawChannel.configureBlocking(false);
						AsynchronousTlsChannelExt asyncTlsChannel = buildAsynchronousTlsChannelExt(channelGroup,
								rawChannel);
						asyncTlsChannel.getTlsChannel().setSslHandshakeTimeout(Duration.ofSeconds(1));
						frontEndRead(asyncTlsChannel, readCounter, writeCounter);
					}
				}
			} catch (Throwable t) {
				if (!(t instanceof InterruptedException) && !(t instanceof CancellationException))
					logger.error("server unexpectedly quit. address:{}", address, t);
				throw t;
			}
			return null;
		});
		return new Tunnel(future, address, readCounter, writeCounter);
	}

	protected void frontEndRead(AsynchronousTlsChannelExt asyncTlsChannel, AtomicLong readCounter,
			AtomicLong writeCounter) {
		ByteBuffer buffer = ByteBuffer.allocate(BYTE_BUFFER_CAPACITY);
		asyncTlsChannel.read(buffer, null, new CompletionHandler<Integer, Object>() {

			private AsynchronousSocketChannel backEndClient;

			@Override
			public void completed(Integer result, Object attachment) {
				try {
					completedThrowing(result, attachment);
				} catch (Throwable t) {
					TunnelUtils.closeAndLogOnError("frontEnd completion error", t, asyncTlsChannel, backEndClient);
				}
			}

			protected void completedThrowing(Integer result, Object attachment) throws IOException {
				if (result == -1) {
					TunnelUtils.closeQuietly(asyncTlsChannel, backEndClient);
					return;
				}
				readCounter.addAndGet(result);
				if (backEndClient == null) {
					backEndClient = createBackEndClient(asyncTlsChannel, () -> {
						this.completed(result, attachment);
					}, writeCounter);
					return;
				}
				buffer.flip();
				CompletionHandler<Integer, Object> readHandler = this;
				backEndClient.write(buffer, attachment, new CompletionHandler<Integer, Object>() {

					@Override
					public void completed(Integer result, Object attachment) {
						buffer.compact();
						asyncTlsChannel.read(buffer, null, readHandler);
					}

					@Override
					public void failed(Throwable exc, Object attachment) {
						TunnelUtils.closeAndLogOnError("frontEnd write error", exc, asyncTlsChannel, backEndClient);
					}
				});

			}

			@Override
			public void failed(Throwable exc, Object attachment) {
				if (TunnelUtils.isCertificateUnknownError(exc))
					return;
				TunnelUtils.closeAndLogOnError("frontEnd read error", exc, asyncTlsChannel, backEndClient);
			}
		});
	}

	protected AsynchronousSocketChannel createBackEndClient(AsynchronousTlsChannelExt asyncTlsChannel,
			Runnable connectCompleteCallback, AtomicLong writeCounter) throws IOException {
		var sniServerName = asyncTlsChannel.getTlsChannel().getSniServerName();
		SocketAddress hostAddress = getBackEndSocketAddress(TunnelUtils.getSNIServerNameValue(sniServerName));
		if (hostAddress == null)
			throw new IOException(TunnelUtils.formatSummary("backEnd server discovery failed.",
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
				writeCounter.addAndGet(result);
				buffer.flip();
				CompletionHandler<Integer, Object> readHandler = this;
				asyncTlsChannel.write(buffer, attachment, new CompletionHandler<Integer, Object>() {

					@Override
					public void completed(Integer result, Object attachment) {
						buffer.compact();
						client.read(buffer, null, readHandler);
					}

					@Override
					public void failed(Throwable exc, Object attachment) {
						TunnelUtils.closeAndLogOnError("backEnd write error", exc, client, asyncTlsChannel);
					}
				});
			}

			@Override
			public void failed(Throwable exc, Object attachment) {
				TunnelUtils.closeAndLogOnError("backEnd read error", exc, client, asyncTlsChannel);

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
				TunnelUtils.closeAndLogOnError("backEnd connect error", exc, client, asyncTlsChannel);
			}
		});
		return client;
	}

	protected AsynchronousTlsChannelExt buildAsynchronousTlsChannelExt(AsynchronousTlsChannelGroup channelGroup,
			SocketChannel rawChannel) throws ClosedChannelException, IllegalArgumentException {
		return new AsynchronousTlsChannelExt(channelGroup, rawChannel, null, v -> getSSLContext(v));
	}

	protected abstract Optional<SSLContext> getSSLContext(Optional<SNIServerName> sniServerNameOp);

	protected abstract SocketAddress getBackEndSocketAddress(Optional<String> sniServerName);

}