package com.lfp.tls.chanel.ext.core;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

public class ByteCounter {

	private final ReadWriteLock listenerLock = new ReentrantReadWriteLock();
	private final Set<Consumer<Event>> listeners = new LinkedHashSet<>();
	private long totalByteCount;

	public long getTotalByteCount() {
		return totalByteCount;
	}

	public long count(long bytesAdded) {
		if (bytesAdded <= 0)
			return totalByteCount;
		totalByteCount = totalByteCount + bytesAdded;
		listeners.forEach(v -> v.accept(new Event(bytesAdded, totalByteCount)));
		return totalByteCount;
	}

	public boolean addListener(Consumer<Event> listener) {
		if (listener == null)
			return false;
		listenerLock.writeLock().lock();
		try {
			return listeners.add(listener);
		} finally {
			listenerLock.writeLock().unlock();
		}
	}

	public boolean removeListener(Consumer<Event> listener) {
		if (listener == null)
			return false;
		listenerLock.writeLock().lock();
		try {
			return listeners.remove(listener);
		} finally {
			listenerLock.writeLock().unlock();
		}
	}

	public static class Event {

		private final long bytesAdded;
		private final long bytesTotal;

		public Event(long bytesAdded, long bytesTotal) {
			super();
			this.bytesAdded = bytesAdded;
			this.bytesTotal = bytesTotal;
		}

		public long getBytesAdded() {
			return bytesAdded;
		}

		public long getBytesTotal() {
			return bytesTotal;
		}

	}

}
