package com.lfp.tls.chanel.ext.core;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;

import tlschannel.async.AsynchronousTlsChannelGroup;

public abstract class TlsTunneler extends AbstractTunneler<ServerSocketChannel, AsynchronousTlsChannelExt> {
	private final AsynchronousTlsChannelGroup channelGroup;
	private final Duration sslHandshakeTimeout;

	public TlsTunneler(Duration sslHandshakeTimeout) throws IOException {
		this(new AsynchronousTlsChannelGroup(), sslHandshakeTimeout);
	}

	public TlsTunneler(AsynchronousTlsChannelGroup channelGroup, Duration sslHandshakeTimeout) throws IOException {
		this.channelGroup = Objects.requireNonNull(channelGroup);
		this.sslHandshakeTimeout = sslHandshakeTimeout;
	}

	@Override
	protected ServerSocketChannel serverBind(SocketAddress address) throws IOException {
		ServerSocketChannel serverSocket = ServerSocketChannel.open();
		try {
			serverSocket.bind(address);
		} catch (IOException t) {
			serverSocket.close();
			throw t;
		}
		return serverSocket;
	}

	@Override
	protected SocketAddress getBackEndSocketAddress(AsynchronousTlsChannelExt byteChannel) {
		var sniServerName = byteChannel.getTlsChannel().getSniServerName();
		return getBackEndSocketAddress(TunnelUtils.getSNIServerNameValue(sniServerName));
	}

	@Override
	protected AsynchronousTlsChannelExt createAsynchronousByteChannel(ServerSocketChannel serverBind)
			throws IOException {
		SocketChannel rawChannel = serverBind.accept();
		rawChannel.configureBlocking(false);
		var asyncTlsChannel = new AsynchronousTlsChannelExt(channelGroup, rawChannel, null, v -> getSSLContext(v));
		if (sslHandshakeTimeout != null)
			asyncTlsChannel.getTlsChannel().setSslHandshakeTimeout(sslHandshakeTimeout);
		return asyncTlsChannel;
	}

	protected abstract SocketAddress getBackEndSocketAddress(Optional<String> sniServerName);

	protected abstract Optional<SSLContext> getSSLContext(Optional<SNIServerName> sniServerNameOp);

}