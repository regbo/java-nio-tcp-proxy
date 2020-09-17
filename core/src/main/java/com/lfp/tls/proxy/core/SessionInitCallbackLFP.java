package com.lfp.tls.proxy.core;

import java.util.Optional;
import java.util.function.Consumer;

import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLSession;

public class SessionInitCallbackLFP implements Consumer<SSLSession> {

	private SNIServerName sniServerName;
	private SSLSession sslSession;

	@Override
	public void accept(SSLSession sslSession) {
		this.sslSession = sslSession;
	}

	public void accept(SNIServerName sniServerName) {
		this.sniServerName = sniServerName;
	}

	public Optional<SNIServerName> getSNIServerName() {
		return Optional.ofNullable(sniServerName);
	}

	public Optional<SSLSession> getSSLSession() {
		return Optional.ofNullable(sslSession);
	}

}
