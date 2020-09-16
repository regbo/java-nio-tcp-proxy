package com.lfp.tls.proxy.core;

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

public interface SSLSessionLFP extends SSLSession {

	public static SSLSessionLFP create(SSLSession sslSession) {
		Objects.requireNonNull(sslSession);
		if (sslSession instanceof SSLSessionLFP)
			return (SSLSessionLFP) sslSession;
		return new SSLSessionLFP.Impl(sslSession);
	}

	default <X> X getAttribute(Class<X> classType) {
		return getAttribute(classType, null);
	}

	<X> X getAttribute(Class<X> classType, Supplier<X> loader);

	<X> void putAttribute(X value);

	<X> void removeAttribute(Class<X> classType);

	public static class Impl implements SSLSessionLFP {
		private static final String KEY_PREPEND = UUID.randomUUID().toString();

		private static String getKey(Class<?> classType) {
			return KEY_PREPEND + "_" + classType.getName();
		}

		private final SSLSession delegate;

		public Impl(SSLSession delegate) {
			this.delegate = Objects.requireNonNull(delegate);
		}

		@SuppressWarnings("unchecked")
		private static <X> X validate(Class<X> classType, Object obj) {
			if (classType == null)
				return null;
			if (obj == null)
				return null;
			if (!classType.isAssignableFrom(obj.getClass()))
				return null;
			return (X) obj;
		}

		public <X> X getAttribute(Class<X> classType, Supplier<X> loader) {
			Objects.requireNonNull(classType);
			String key = getKey(classType);
			X result = validate(classType, this.getValue(key));
			if (result != null || loader == null)
				return result;
			synchronized (this) {
				result = validate(classType, this.getValue(key));
				if (result == null) {
					result = validate(classType, loader.get());
					if (result != null)
						this.putValue(key, result);
				}
			}
			return result;
		}

		public <X> void putAttribute(X value) {
			Objects.requireNonNull(value);
			String key = getKey(value.getClass());
			this.removeValue(key);
			this.putValue(key, value);
		}

		public <X> void removeAttribute(Class<X> classType) {
			Objects.requireNonNull(classType);
			String key = getKey(classType);
			removeValue(key);
		}

		@Override
		public byte[] getId() {
			return delegate.getId();
		}

		@Override
		public SSLSessionContext getSessionContext() {
			return delegate.getSessionContext();
		}

		@Override
		public long getCreationTime() {
			return delegate.getCreationTime();
		}

		@Override
		public long getLastAccessedTime() {
			return delegate.getLastAccessedTime();
		}

		@Override
		public void invalidate() {
			delegate.invalidate();
		}

		@Override
		public boolean isValid() {
			return delegate.isValid();
		}

		@Override
		public void putValue(String name, Object value) {
			delegate.putValue(name, value);
		}

		@Override
		public Object getValue(String name) {
			return delegate.getValue(name);
		}

		@Override
		public void removeValue(String name) {
			delegate.removeValue(name);
		}

		@Override
		public String[] getValueNames() {
			return delegate.getValueNames();
		}

		@Override
		public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
			return delegate.getPeerCertificates();
		}

		@Override
		public Certificate[] getLocalCertificates() {
			return delegate.getLocalCertificates();
		}

		@Override
		public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
			return delegate.getPeerCertificateChain();
		}

		@Override
		public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
			return delegate.getPeerPrincipal();
		}

		@Override
		public Principal getLocalPrincipal() {
			return delegate.getLocalPrincipal();
		}

		@Override
		public String getCipherSuite() {
			return delegate.getCipherSuite();
		}

		@Override
		public String getProtocol() {
			return delegate.getProtocol();
		}

		@Override
		public String getPeerHost() {
			return delegate.getPeerHost();
		}

		@Override
		public int getPeerPort() {
			return delegate.getPeerPort();
		}

		@Override
		public int getPacketBufferSize() {
			return delegate.getPacketBufferSize();
		}

		@Override
		public int getApplicationBufferSize() {
			return delegate.getApplicationBufferSize();
		}

	}

}
