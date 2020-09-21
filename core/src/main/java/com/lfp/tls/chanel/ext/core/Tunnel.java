package com.lfp.tls.chanel.ext.core;

import java.net.SocketAddress;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

public class Tunnel implements Future<Void> {

	private final Future<Void> delegate;
	private final SocketAddress backEndAddress;
	private AtomicLong readCounter;
	private AtomicLong writeCounter;

	public Tunnel(Future<Void> delegate, SocketAddress backEndAddress, AtomicLong readCounter,
			AtomicLong writeCounter) {
		this.delegate = Objects.requireNonNull(delegate);
		this.backEndAddress = Objects.requireNonNull(backEndAddress);
		this.readCounter = Objects.requireNonNull(readCounter);
		this.writeCounter = Objects.requireNonNull(writeCounter);
	}

	public SocketAddress getBackEndAddress() {
		return backEndAddress;
	}

	public long getReadCount() {
		return readCounter.get();
	}

	public long getWriteCount() {
		return writeCounter.get();
	}

	@Override
	public boolean cancel(boolean mayInterruptIfRunning) {
		return delegate.cancel(mayInterruptIfRunning);
	}

	@Override
	public boolean isCancelled() {
		return delegate.isCancelled();
	}

	@Override
	public boolean isDone() {
		return delegate.isDone();
	}

	@Override
	public Void get() throws InterruptedException, ExecutionException {
		return delegate.get();
	}

	@Override
	public Void get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
		return delegate.get(timeout, unit);
	}

}
