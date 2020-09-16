package com.lfp.tls.proxy.core;

import java.io.Closeable;
import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.ByteChannel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;

import javax.net.ssl.SNIServerName;

import com.github.terma.javaniotcpserver.TcpServerHandler;

import tlschannel.NeedsReadException;
import tlschannel.NeedsWriteException;
import tlschannel.ServerTlsChannel;
import tlschannel.SniSslContextFactory;

public class TcpServerHandlerLFP implements TcpServerHandler {

	private static final Class<?> THIS_CLASS = new Object() {
	}.getClass().getEnclosingClass();
	private static final java.util.logging.Logger logger = java.util.logging.Logger.getLogger(THIS_CLASS.getName());

	private final TcpProxyBufferLFP clientBuffer = new TcpProxyBufferLFP();
	private final TcpProxyBufferLFP serverBuffer = new TcpProxyBufferLFP();
	private final SocketChannel clientChannel;
	private final SniSslContextFactory sniSslContextFactory;
	private Selector selector;
	private SocketChannel serverChannel;
	private TcpDynamicProxyConfig config;
	private Optional<ServerTlsChannel> clientTlsChannelOp;

	public TcpServerHandlerLFP(TcpDynamicProxyConfig config, SocketChannel clientChannel,
			SniSslContextFactory sniSslContextFactory) {
		this.config = config;
		this.clientChannel = clientChannel;
		this.sniSslContextFactory = sniSslContextFactory;
	}

	public void readFromClient(SelectionKey key) throws IOException {
		ByteChannel byteChannel = clientTlsChannelOp != null && clientTlsChannelOp.isPresent()
				? clientTlsChannelOp.get()
				: clientChannel;
		try {
			serverBuffer.writeFrom(byteChannel);
			if (serverBuffer.isReadyToRead())
				register();
		} catch (NeedsReadException e) {
			key.interestOps(SelectionKey.OP_READ); // overwrites previous value
		} catch (NeedsWriteException e) {
			key.interestOps(SelectionKey.OP_WRITE); // overwrites previous value
		}
	}

	public void readFromServer() throws IOException {
		clientBuffer.writeFrom(serverChannel);
		if (clientBuffer.isReadyToRead())
			register();
	}

	public void writeToClient(SelectionKey key) throws IOException {
		ByteChannel byteChannel = clientTlsChannelOp != null && clientTlsChannelOp.isPresent()
				? clientTlsChannelOp.get()
				: clientChannel;
		try {
			clientBuffer.writeTo(byteChannel);
			if (clientBuffer.isReadyToWrite())
				register();
		} catch (NeedsReadException e) {
			key.interestOps(SelectionKey.OP_READ); // overwrites previous value
		} catch (NeedsWriteException e) {
			key.interestOps(SelectionKey.OP_WRITE); // overwrites previous value
		}

	}

	public void writeToServer() throws IOException {
		serverBuffer.writeTo(serverChannel);
		if (serverBuffer.isReadyToWrite())
			register();
	}

	public void register() throws ClosedChannelException {
		int clientOps = 0;
		if (serverBuffer.isReadyToWrite())
			clientOps |= SelectionKey.OP_READ;
		if (clientBuffer.isReadyToRead())
			clientOps |= SelectionKey.OP_WRITE;
		clientChannel.register(selector, clientOps, this);

		int serverOps = 0;
		if (clientBuffer.isReadyToWrite())
			serverOps |= SelectionKey.OP_READ;
		if (serverBuffer.isReadyToRead())
			serverOps |= SelectionKey.OP_WRITE;
		if (serverChannel != null && serverChannel.isConnected())
			serverChannel.register(selector, serverOps, this);
	}

	private static void closeQuietly(Closeable channel) {
		if (channel != null) {
			try {
				channel.close();
			} catch (IOException exception) {
				logger.log(Level.WARNING, "Could not close channel properly.", exception);
			}
		}
	}

	@Override
	public void register(Selector selector) {
		this.selector = selector;
		SocketAddress serverChannelSocketAddress = null;
		try {
			clientChannel.configureBlocking(false);
			if (clientTlsChannelOp == null) {
				if (this.sniSslContextFactory != null) {
					this.clientTlsChannelOp = Optional.of(createServerTlsChannel());
					int clientOps = 0;
					clientOps |= SelectionKey.OP_READ;
					clientOps |= SelectionKey.OP_WRITE;
					clientChannel.register(selector, clientOps, this);
				} else
					clientTlsChannelOp = Optional.empty();
			}
			serverChannel = SocketChannel.open();
			if (clientTlsChannelOp.isEmpty()) {
				serverChannelSocketAddress = createServerChannelSocketAddress(Optional.empty());
				serverChannelConnect(serverChannelSocketAddress);
			}
			register();
		} catch (final IOException e) {
			destroy();
			logger.log(Level.WARNING,
					String.format(
							"serverChannel connection failed. serverChannelSocketAddress:%s clientTlsChannelPresent:%s",
							serverChannelSocketAddress, clientTlsChannelOp.isPresent()),
					e);
		}
	}

	protected ServerTlsChannel createServerTlsChannel() {
		AtomicReference<SNIServerName> sniServerNameRef = new AtomicReference<>();
		ServerTlsChannel.Builder builder = ServerTlsChannel.newBuilder(clientChannel, sniServerNameOp -> {
			sniServerNameRef.set(sniServerNameOp.orElse(null));
			if (this.sniSslContextFactory == null)
				return Optional.empty();
			var resultOp = this.sniSslContextFactory.getSslContext(sniServerNameOp);
			if (resultOp == null)
				return Optional.empty();
			return resultOp;
		}).withSessionInitCallback(ssls -> {
			SSLSessionLFP sslSession = SSLSessionLFP.create(ssls);
			if (sniServerNameRef.get() != null)
				sslSession.putAttribute(sniServerNameRef.get());
			var serverChannelSocketAddress = createServerChannelSocketAddress(Optional.of(sslSession));
			try {
				serverChannelConnect(serverChannelSocketAddress);
			} catch (IOException e) {
				destroy();
				logger.log(Level.WARNING, String.format(
						"serverChannel connection failed. serverChannelSocketAddress:%s clientTlsChannelPresent:%s",
						serverChannelSocketAddress, clientTlsChannelOp.isPresent()), e);
			}
		});
		return builder.build();
	}

	protected void serverChannelConnect(SocketAddress inetSocketAddress) throws IOException {
		serverChannel.connect(inetSocketAddress);
		serverChannel.configureBlocking(false);
	}

	protected SocketAddress createServerChannelSocketAddress(Optional<SSLSessionLFP> sslSessionOptional) {
		final SocketAddress socketAddress = this.config.getRemoteSocketAddressGenerator().apply(sslSessionOptional);
		return socketAddress;
	}

	@Override
	public void process(final SelectionKey key) {
		try {
			if (key.channel() == clientChannel) {
				if (key.isValid() && key.isReadable())
					readFromClient(key);
				if (key.isValid() && key.isWritable())
					writeToClient(key);
			}

			if (key.channel() == serverChannel) {
				if (key.isValid() && key.isReadable())
					readFromServer();
				if (key.isValid() && key.isWritable())
					writeToServer();
			}
		} catch (final ClosedChannelException exception) {
			destroy();
			logger.log(Level.FINEST, "Channel was closed by client or server.", exception);
		} catch (final IOException exception) {
			destroy();
			logger.log(Level.WARNING, "Could not process.", exception);
		}
	}

	@Override
	public void destroy() {
		closeQuietly(clientChannel);
		closeQuietly(serverChannel);
		if (clientTlsChannelOp != null)
			closeQuietly(clientTlsChannelOp.orElse(null));
	}

}
