package test;

import static test.SelectorProcessor.*;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.threadly.concurrent.future.FutureUtils;
import org.threadly.concurrent.future.ListenableFuture;

import com.lfp.joe.threads.Threads;
import com.lfp.joe.utils.Utils;
import com.lfp.joe.utils.function.Throwing.ThrowingBiConsumer;
import com.lfp.joe.utils.function.Throwing.ThrowingSupplier;

public interface SelectorProcessor {

	default CompletableFuture<Void> start(Executor executor, Selector selector) {
		Objects.requireNonNull(selector);
		return start(executor, () -> Arrays.asList(selector));
	}

	CompletableFuture<Void> start(Executor executor,
			ThrowingSupplier<? extends Iterable<Selector>, IOException> selectorsSupplier);

	public static SelectorProcessor createUnchecked(
			ThrowingBiConsumer<List<Selector>, SelectionKey, IOException> processor) {
		return create(processor, errorDetails -> {
			throw Utils.Exceptions.asRuntimeException(errorDetails.getError());
		});
	}

	public static SelectorProcessor createLogging(
			ThrowingBiConsumer<List<Selector>, SelectionKey, IOException> processor) {
		return create(processor, errorDetails -> {
			getLogger().error(getErrorMessage("processing error", errorDetails), errorDetails.getError());
			return false;
		});
	}

	public static SelectorProcessor create(ThrowingBiConsumer<List<Selector>, SelectionKey, IOException> processor,
			Function<SelectorProcessorErrorDetails, Boolean> onError) {
		Objects.requireNonNull(processor);
		Objects.requireNonNull(onError);
		return new SelectorProcessor.Abs() {

			@Override
			protected void process(List<Selector> selectors, SelectionKey key) throws IOException {
				processor.accept(selectors, key);
			}

			@Override
			protected Boolean onProcessError(SelectorProcessorErrorDetails errorDetails) {
				return onError.apply(errorDetails);
			}
		};
	}

	public static abstract class Abs implements SelectorProcessor {
		final Class<?> THIS_CLASS = new Object() {
		}.getClass().getEnclosingClass();
		org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(THIS_CLASS);

		@Override
		public CompletableFuture<Void> start(Executor executor,
				ThrowingSupplier<? extends Iterable<Selector>, IOException> selectorsSupplier) {
			Objects.requireNonNull(selectorsSupplier);
			Supplier<Void> supplier = () -> {
				run(selectorsSupplier);
				return null;
			};
			CompletableFuture<Void> result;
			if (executor == null)
				result = CompletableFuture.supplyAsync(supplier);
			else
				result = CompletableFuture.supplyAsync(supplier, executor);
			result = result.whenComplete((v, t) -> {
				if (t == null || Utils.Exceptions.isCancelException(t))
					return;
				var errorDetails = SelectorProcessorErrorDetails.builder().error(t).build();
				logger.trace(getErrorMessage("unexpected error", errorDetails), t);
			});
			return result;
		}

		protected void run(ThrowingSupplier<? extends Iterable<Selector>, IOException> selectorSupplier) {
			List<Selector> selectors;
			{// exit thread if selector open fails
				try {
					selectors = Utils.Lots.stream(selectorSupplier.get()).nonNull().toList();
					Validate.isTrue(!selectors.isEmpty(), "no selectors found");
				} catch (Throwable t) {
					var errorDetails = SelectorProcessorErrorDetails.builder().error(t).build();
					onError(errorDetails);
					return;
				}
			}
			boolean errorQuit = false;
			while (!errorQuit && !Thread.currentThread().isInterrupted()) {
				try {
					while (!errorQuit && !Thread.currentThread().isInterrupted()) {
						var selector = waitForSelector(selectors);
						if (selector == null)
							continue;
						var selectedKeys = selector.selectedKeys();
						var selectedKeysIter = selectedKeys.iterator();
						while (!errorQuit && selectedKeysIter.hasNext()) {
							SelectionKey key = selectedKeysIter.next();
							selectedKeysIter.remove();
							try {
								process(Collections.unmodifiableList(selectors), key);
							} catch (Throwable t) {
								var errorDetails = SelectorProcessorErrorDetails.builder().error(t).selectors(selectors)
										.key(key).build();
								errorQuit = onError(errorDetails);
							}
						}
					}
				} catch (Throwable t) {
					var errorDetails = SelectorProcessorErrorDetails.builder().error(t).selectors(selectors).build();
					errorQuit = onError(errorDetails);
				}
			}
		}

		protected boolean onError(SelectorProcessorErrorDetails errorDetails) {
			if (errorDetails.getError() instanceof ClosedChannelException) {
				logger.trace(getErrorMessage("channel close", errorDetails), errorDetails.getError());
				return false;
			}
			return Boolean.TRUE.equals(onProcessError(errorDetails));
		}

		protected abstract void process(List<Selector> selectors, SelectionKey key) throws IOException;

		protected abstract Boolean onProcessError(SelectorProcessorErrorDetails errorDetails);
	}

	private static Selector waitForSelector(List<Selector> selectors) throws IOException, InterruptedException {
		Validate.isTrue(!selectors.isEmpty(), "selectors required");
		if (selectors.size() == 1) {
			var selector = selectors.get(0);
			selector.select();
			return selector;
		}
		for (int i = 0; i < selectors.size(); i++) {
			var selector = selectors.remove(0);
			selectors.add(selector);
			if (selector.selectNow() > 0)
				return selector;
		}
		LinkedBlockingQueue<Optional<Selector>> successQueue = new LinkedBlockingQueue<>();
		List<ListenableFuture<Void>> selectFutures = new ArrayList<>();
		for (var selector : selectors) {
			AtomicBoolean selecting = new AtomicBoolean();
			ListenableFuture<Void> selectFuture = Threads.CentralPool.unlimitedPool().submit(() -> {
				selecting.set(true);
				var selected = selector.select();
				selecting.set(false);
				if (selected > 0)
					successQueue.add(Optional.of(selector));
				return null;
			});
			Threads.Futures.callback(selectFuture, () -> {
				if (selecting.get())
					selector.wakeup();
			});
			Threads.Futures.logFailureERROR(selectFuture, true, "error while waiting for selector:{}", selector);
			selectFutures.add(selectFuture);
		}
		Threads.Futures.callback(FutureUtils.makeCompleteFuture(selectFutures),
				() -> successQueue.add(Optional.empty()));
		var selectorOp = successQueue.take();
		for (var selectFuture : selectFutures)
			Threads.Futures.cancel(selectFuture, true);
		return selectorOp.orElse(null);
	}

	private static String getErrorMessage(String message, SelectorProcessorErrorDetails errorDetails) {
		Objects.requireNonNull(errorDetails);
		if (Utils.Strings.isBlank(message))
			message = errorDetails.getError().getMessage();
		StringBuilder sb = new StringBuilder();
		sb.append(message);
		errorDetails.getKey().ifPresent(v -> sb.append(String.format(" [%s]", v)));
		return sb.toString();
	}

	private static Logger getLogger() {
		org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SelectorProcessor.class);
		return logger;
	}
}
