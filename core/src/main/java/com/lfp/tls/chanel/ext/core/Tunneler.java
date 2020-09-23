package com.lfp.tls.chanel.ext.core;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.AsynchronousByteChannel;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;

public abstract class Tunneler extends AbstractTunneler<AsynchronousServerSocketChannel, AsynchronousByteChannel> {

	private AsynchronousChannelGroup asynchronousChannelGroup;

	public Tunneler() {
		this(TunnelUtils.unchecked(() -> AsynchronousChannelGroup
				.withFixedThreadPool(Runtime.getRuntime().availableProcessors(), Executors.defaultThreadFactory())));
	}

	public Tunneler(AsynchronousChannelGroup asynchronousChannelGroup) {
		this.asynchronousChannelGroup = Objects.requireNonNull(asynchronousChannelGroup);
	}

	@Override
	protected AsynchronousServerSocketChannel serverBind(SocketAddress address) throws IOException {
		var serverSocket = AsynchronousServerSocketChannel.open(this.asynchronousChannelGroup);
		try {
			serverSocket.bind(address);
		} catch (IOException t) {
			serverSocket.close();
			throw t;
		}
		return serverSocket;
	}

	@Override
	protected AsynchronousByteChannel createAsynchronousByteChannel(AsynchronousServerSocketChannel serverBind)
			throws IOException {
		AsynchronousSocketChannel rawChannel;
		try {
			rawChannel = serverBind.accept().get();
		} catch (InterruptedException | ExecutionException e) {
			throw (((Object) e) instanceof java.lang.RuntimeException) ? java.lang.RuntimeException.class.cast(e)
					: new RuntimeException(e);
		}
		return rawChannel;
	}

}
