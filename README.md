# java-nio-tls-proxy

# secure sni/tls routing in java	
This library is the love child of:
https://github.com/marianobarrios/tls-channel
and
https://github.com/terma/java-nio-tcp-proxy

With the below example, you can listen on port 6969, decrypt the connection, and forward it to port 8181.

	TcpDynamicProxyConfig config = TcpDynamicProxyConfig.builder().withLocalPort(6969)
			.withRemoteSocketAddressGenerator(op -> {
				return new InetSocketAddress("localhost", 8181);
			}).build();
	var sslContext = createSSLContext();
	TcpProxyLFP proxy = new TcpProxyLFP(config, op -> {
		return Optional.of(sslContext);
	});
	proxy.start();
	System.out.println("started");
	Thread.currentThread().join();

