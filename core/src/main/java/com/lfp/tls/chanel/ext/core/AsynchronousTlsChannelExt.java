package com.lfp.tls.chanel.ext.core;

import java.nio.channels.ClosedChannelException;
import java.nio.channels.SocketChannel;
import java.util.function.Consumer;

import javax.net.ssl.SSLContext;

import tlschannel.ServerTlsChannel;
import tlschannel.SniSslContextFactory;
import tlschannel.TlsChannel;
import tlschannel.async.AsynchronousTlsChannel;
import tlschannel.async.AsynchronousTlsChannelGroup;

public class AsynchronousTlsChannelExt extends AsynchronousTlsChannel {

	public AsynchronousTlsChannelExt(AsynchronousTlsChannelGroup channelGroup, SocketChannel socketChannel,
			Consumer<ServerTlsChannel.Builder> builderModifier, SniSslContextFactory... sniSslContextFactories)
			throws ClosedChannelException, IllegalArgumentException {
		this(channelGroup, new ServerTlsChannelExt(socketChannel, builderModifier, sniSslContextFactories));
	}

	public AsynchronousTlsChannelExt(AsynchronousTlsChannelGroup channelGroup, SocketChannel socketChannel,
			Consumer<ServerTlsChannel.Builder> builderModifier, SSLContext fixedSSLContext)
			throws ClosedChannelException, IllegalArgumentException {
		this(channelGroup, new ServerTlsChannelExt(socketChannel, builderModifier, fixedSSLContext));
	}

	public AsynchronousTlsChannelExt(AsynchronousTlsChannelGroup channelGroup, ServerTlsChannelExt tlsChannel)
			throws ClosedChannelException, IllegalArgumentException {
		super(channelGroup, tlsChannel, (SocketChannel) (tlsChannel == null ? null : tlsChannel.getUnderlying()));
	}

	public ServerTlsChannelExt getTlsChannel() {
		return (ServerTlsChannelExt) TunnelUtils.uncheckedFieldAccess(this, "tlsChannel", TlsChannel.class,
				(getter, setter) -> getter.get());
	}

}
