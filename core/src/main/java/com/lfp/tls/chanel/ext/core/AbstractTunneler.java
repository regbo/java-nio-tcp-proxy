package com.lfp.tls.chanel.ext.core;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousByteChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public abstract class AbstractTunneler<SERVER extends Closeable, ABC extends AsynchronousByteChannel> {
	private static final Class<?> THIS_CLASS = new Object() {
	}.getClass().getEnclosingClass();
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(THIS_CLASS);
	private static final int BYTE_BUFFER_CAPACITY = 10_000;
	private static final ExecutorService RUNNING_EXECUTOR_SERVICE = Executors.newCachedThreadPool();

	public Tunnel start(InetSocketAddress address) {
		Objects.requireNonNull(address);
		ByteCounter readCounter = new ByteCounter();
		ByteCounter writeCounter = new ByteCounter();
		Future<Void> future = RUNNING_EXECUTOR_SERVICE.submit(() -> {
			try {
				// connect server socket channel and register it in the selector
				try (SERVER serverBind = serverBind(address)) {
					logger.info("listening for connections:{}", address);
					while (!Thread.currentThread().isInterrupted()) {
						ABC byteChannel = createAsynchronousByteChannel(serverBind);
						frontEndRead(byteChannel, readCounter, writeCounter);
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

	protected void frontEndRead(ABC byteChannel, ByteCounter readCounter, ByteCounter writeCounter) {
		ByteBuffer buffer = ByteBuffer.allocate(BYTE_BUFFER_CAPACITY);
		byteChannel.read(buffer, null, new CompletionHandler<Integer, Object>() {

			private AsynchronousSocketChannel backEndClient;

			@Override
			public void completed(Integer result, Object attachment) {
				try {
					completedThrowing(result, attachment);
				} catch (Throwable t) {
					TunnelUtils.closeAndLogOnError("frontEnd completion error", t, byteChannel, backEndClient);
				}
			}

			protected void completedThrowing(Integer result, Object attachment) throws IOException {
				if (result == -1) {
					TunnelUtils.closeQuietly(byteChannel, backEndClient);
					return;
				}
				readCounter.count(result);
				if (backEndClient == null) {
					backEndClient = createBackEndClient(byteChannel, () -> {
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
						byteChannel.read(buffer, null, readHandler);
					}

					@Override
					public void failed(Throwable exc, Object attachment) {
						TunnelUtils.closeAndLogOnError("frontEnd write error", exc, byteChannel, backEndClient);
					}
				});

			}

			@Override
			public void failed(Throwable exc, Object attachment) {
				if (TunnelUtils.isCertificateUnknownError(exc))
					return;
				TunnelUtils.closeAndLogOnError("frontEnd read error", exc, byteChannel, backEndClient);
			}
		});
	}

	protected AsynchronousSocketChannel createBackEndClient(ABC byteChannel, Runnable connectCompleteCallback,
			ByteCounter writeCounter) throws IOException {
		SocketAddress hostAddress = getBackEndSocketAddress(byteChannel);
		if (hostAddress == null)
			throw new IOException(
					TunnelUtils.formatSummary("backEnd server discovery failed.", TunnelUtils.getSummary(byteChannel)));
		AsynchronousSocketChannel client = AsynchronousSocketChannel.open();
		ByteBuffer buffer = ByteBuffer.allocate(BYTE_BUFFER_CAPACITY);
		var readHandler = new CompletionHandler<Integer, Object>() {

			@Override
			public void completed(Integer result, Object attachment) {
				if (result == -1) {
					TunnelUtils.closeQuietly(client, byteChannel);
					return;
				}
				writeCounter.count(result);
				buffer.flip();
				CompletionHandler<Integer, Object> readHandler = this;
				byteChannel.write(buffer, attachment, new CompletionHandler<Integer, Object>() {

					@Override
					public void completed(Integer result, Object attachment) {
						buffer.compact();
						client.read(buffer, null, readHandler);
					}

					@Override
					public void failed(Throwable exc, Object attachment) {
						TunnelUtils.closeAndLogOnError("backEnd write error", exc, client, byteChannel);
					}
				});
			}

			@Override
			public void failed(Throwable exc, Object attachment) {
				TunnelUtils.closeAndLogOnError("backEnd read error", exc, client, byteChannel);

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
				TunnelUtils.closeAndLogOnError("backEnd connect error", exc, client, byteChannel);
			}
		});
		return client;
	}

	protected abstract SERVER serverBind(SocketAddress address) throws IOException;

	protected abstract ABC createAsynchronousByteChannel(SERVER serverBind) throws IOException;

	protected abstract SocketAddress getBackEndSocketAddress(ABC byteChannel);

}