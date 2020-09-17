package test;

import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;

public abstract class SyncedSelector implements Callable<Void>, Closeable {
	private static final Class<?> THIS_CLASS = new Object() {
	}.getClass().getEnclosingClass();
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(THIS_CLASS);

	public static SyncedSelector create() throws IOException {
		return create(Selector.open());
	}

	public static SyncedSelector create(Selector selector) {
		return create(selector, (k, t) -> {
			logger.error("error during processing:{}", k, t);
		});
	}

	public static SyncedSelector create(Selector selector, BiConsumer<SelectionKey, Throwable> onError) {
		return new SyncedSelector(selector) {

			@Override
			protected void processError(SelectionKey key, Throwable error) {
				if (onError == null)
					throw (((Object) error) instanceof java.lang.RuntimeException)
							? ((java.lang.RuntimeException) error)
							: new RuntimeException(error);
				onError.accept(key, error);
			}
		};
	}

	private final ReentrantLock selectLock = new ReentrantLock();
	private final ReentrantLock wakeLock = new ReentrantLock();
	private final List<SelectionKeyProcessor> processors = new CopyOnWriteArrayList<>();
	private final Selector selector;
	private boolean closed;

	public SyncedSelector(Selector selector) {
		this.selector = Objects.requireNonNull(selector);
	}

	@Override
	public Void call() throws Exception {
		if (processors.isEmpty())
			logger.warn("started synchronized selector with no processors attached");
		while (!closed) {
			System.out.println("start select");
			selectLock.lock();
			try {
				selector.select();
				System.out.println("done wakeup 1");
			} finally {
				selectLock.unlock();
				wakeLock.lock();
				wakeLock.unlock();
			}
			System.out.println("done select");
			var selectedKeys = selector.selectedKeys();
			keyIteratorProcess(selectedKeys);
		}
		if (!closed)
			throw new IllegalStateException("processing complete without closure");
		return null;
	}

	public SelectionKey register(SelectableChannel channel, int ops) throws ClosedChannelException {
		return register(channel, ops, null);
	}

	public SelectionKey register(SelectableChannel channel, int ops, Object attachment) throws ClosedChannelException {
		Objects.requireNonNull(channel);
		SelectionKey selectionKey;
		System.out.println("start wakeup");
		wakeLock.lock();
		try {
			selector.wakeup();
			System.out.println("done wakeup 1");
			selectionKey = channel.register(selector, ops, attachment);
			System.out.println("done wakeup 2");
		} finally {
			wakeLock.unlock();
			selectLock.lock();
			selectLock.unlock();
		}

		System.out.println("done wakeup");
		return selectionKey;

	}

	@Override
	public void close() throws IOException {
		this.closed = true;
		selector.close();
	}

	private void keyIteratorProcess(Set<SelectionKey> selectedKeys) {
		var iter = selectedKeys.iterator();
		while (!closed && iter.hasNext()) {
			var key = iter.next();
			iter.remove();
			try {
				for (var process : processors)
					process.process(key);
			} catch (Throwable t) {
				processError(key, t);
			}
		}

	}

	public boolean addProcessor(SelectionKeyProcessor processor) {
		if (closed)
			throw new IllegalStateException("closed");
		if (processor == null)
			return false;
		return this.processors.add(processor);
	}

	protected abstract void processError(SelectionKey key, Throwable error);

	public static interface SelectionKeyProcessor {

		void process(SelectionKey key) throws IOException;
	}
}
