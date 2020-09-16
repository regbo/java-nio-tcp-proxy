package com.lfp.tls.proxy.core;

import java.net.SocketAddress;
import java.util.Optional;
import java.util.function.Function;

import javax.annotation.processing.Generated;

public class TcpDynamicProxyConfig {

	private final int localPort;
	private final int workerCount;
	private final Function<Optional<SSLSessionLFP>, SocketAddress> remoteSocketAddressGenerator;

	public int getLocalPort() {
		return localPort;
	}

	public int getWorkerCount() {
		return workerCount;
	}

	public Function<Optional<SSLSessionLFP>, SocketAddress> getRemoteSocketAddressGenerator() {
		return remoteSocketAddressGenerator;
	}

	@Generated("SparkTools")
	private TcpDynamicProxyConfig(Builder builder) {
		this.localPort = builder.localPort;
		this.workerCount = builder.workerCount;
		this.remoteSocketAddressGenerator = builder.remoteSocketAddressGenerator;
	}

	/**
	 * Creates builder to build {@link TcpDynamicProxyConfig}.
	 * 
	 * @return created builder
	 */
	@Generated("SparkTools")
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Creates a builder to build {@link TcpDynamicProxyConfig} and initialize it
	 * with the given object.
	 * 
	 * @param tcpDynamicProxyConfig to initialize the builder with
	 * @return created builder
	 */
	@Generated("SparkTools")
	public static Builder builderFrom(TcpDynamicProxyConfig tcpDynamicProxyConfig) {
		return new Builder(tcpDynamicProxyConfig);
	}

	/**
	 * Builder to build {@link TcpDynamicProxyConfig}.
	 */
	@Generated("SparkTools")
	public static final class Builder {
		private int localPort;
		private int workerCount = Runtime.getRuntime().availableProcessors() * 2;
		private Function<Optional<SSLSessionLFP>, SocketAddress> remoteSocketAddressGenerator;

		private Builder() {
		}

		private Builder(TcpDynamicProxyConfig tcpDynamicProxyConfig) {
			this.localPort = tcpDynamicProxyConfig.localPort;
			this.workerCount = tcpDynamicProxyConfig.workerCount;
			this.remoteSocketAddressGenerator = tcpDynamicProxyConfig.remoteSocketAddressGenerator;
		}

		public Builder withLocalPort(int localPort) {
			this.localPort = localPort;
			return this;
		}

		public Builder withWorkerCount(int workerCount) {
			this.workerCount = workerCount;
			return this;
		}

		public Builder withRemoteSocketAddressGenerator(
				Function<Optional<SSLSessionLFP>, SocketAddress> remoteSocketAddressGenerator) {
			this.remoteSocketAddressGenerator = remoteSocketAddressGenerator;
			return this;
		}

		public TcpDynamicProxyConfig build() {
			return new TcpDynamicProxyConfig(this);
		}
	}

}
