package com.lfp.tls.proxy.core;

import java.nio.channels.SocketChannel;

import com.github.terma.javaniotcpserver.TcpServer;
import com.github.terma.javaniotcpserver.TcpServerConfig;
import com.github.terma.javaniotcpserver.TcpServerHandler;
import com.github.terma.javaniotcpserver.TcpServerHandlerFactory;

import tlschannel.SniSslContextFactory;

public class TcpProxyLFP {

	private TcpServer server;
	private SniSslContextFactory sniSslContextFactory;

	public TcpProxyLFP(TcpDynamicProxyConfig config, SniSslContextFactory sniSslContextFactory) {
		this.sniSslContextFactory = sniSslContextFactory;
		TcpServerHandlerFactory tcpServerHandlerFactory = (clientChannel) -> createTcpServerHandler(config,
				clientChannel);
		final TcpServerConfig serverConfig = new TcpServerConfig(config.getLocalPort(), tcpServerHandlerFactory,
				config.getWorkerCount());
		this.server = new TcpServer(serverConfig);

	}

	protected TcpServerHandler createTcpServerHandler(TcpDynamicProxyConfig config, SocketChannel clientChannel) {
		return new TcpServerHandlerLFP(config, clientChannel, sniSslContextFactory);
	}

	public void start() {
		server.start();
	}

	public void shutdown() {
		server.shutdown();
	}

}
