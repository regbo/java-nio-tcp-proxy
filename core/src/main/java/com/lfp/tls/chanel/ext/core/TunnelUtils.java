package com.lfp.tls.chanel.ext.core;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.channels.AsynchronousByteChannel;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ByteChannel;
import java.nio.channels.Channel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLHandshakeException;

import tlschannel.TlsChannel;

public class TunnelUtils {
	private static final Class<?> THIS_CLASS = new Object() {
	}.getClass().getEnclosingClass();
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(THIS_CLASS);
	private static final Map<String, Field> _FIELD_REFLECTION_CACHE = new ConcurrentHashMap<>();

	@SuppressWarnings("unchecked")
	public static <F, X> X uncheckedFieldAccess(Object declaringObject, String fieldName, Class<F> fieldType,
			BiFunction<Supplier<F>, Consumer<F>, X> reflectAccess) {
		Objects.requireNonNull(declaringObject);
		String cacheKey = Arrays.asList(declaringObject.getClass(), fieldName, fieldType).stream()
				.map(Objects::requireNonNull).map(v -> {
					if (v instanceof Class)
						return ((Class<?>) v).getName();
					return v.toString();
				}).collect(Collectors.joining("#"));
		var field = _FIELD_REFLECTION_CACHE.computeIfAbsent(cacheKey, nil -> {
			Stream<Field> fieldStream = streamHierarcy(declaringObject.getClass()).map(v -> {
				Stream<Field> stream = Stream.of();
				stream = Stream.concat(stream, Stream.of(v.getDeclaredFields()));
				stream = Stream.concat(stream, Stream.of(v.getFields()));
				stream = stream.distinct();
				stream = stream.filter(f -> fieldName.equals(f.getName()));
				stream = stream.filter(f -> fieldType.isAssignableFrom(f.getType()));
				return stream;
			}).flatMap(v -> v).distinct();
			var fields = fieldStream.limit(2).collect(Collectors.toList());
			if (fields.size() != 1)
				throw new NoSuchElementException(String.format(
						"field lookup failed. declaringType:%s fieldName:%s fieldType:%s",
						declaringObject == null ? null : declaringObject.getClass().getName(), fieldName, fieldType));
			var result = fields.get(0);
			result.setAccessible(true);
			return result;
		});
		return reflectAccess.apply(() ->

		{
			return (F) unchecked(() -> field.get(declaringObject));
		}, v -> {
			unchecked(() -> {
				field.set(declaringObject, v);
				return null;
			});
		});
	}

	private static Stream<Class<?>> streamHierarcy(Class<?> classType) {
		if (classType == null)
			return Stream.of(classType);
		Stream<Class<?>> stream = Stream.of(classType);
		stream = Stream.concat(stream, streamHierarcy(classType.getSuperclass()));
		return stream.filter(Objects::nonNull).distinct();
	}

	public static <X> X unchecked(Callable<X> callable) {
		try {
			return callable.call();
		} catch (Exception e) {
			throw (((Object) e) instanceof java.lang.RuntimeException) ? java.lang.RuntimeException.class.cast(e)
					: new RuntimeException(e);
		}
	}

	@SuppressWarnings("unchecked")
	public static <X, T extends Throwable> X tryThrowAs(Exception exception, Class<T> exceptionType) throws T {
		if (exceptionType == null)
			throw new RuntimeException();
		if (exceptionType.isAssignableFrom(exception.getClass()))
			throw (T) exception;
		throw new RuntimeException(exception);
	}

	public static boolean closeQuietly(Closeable... closeables) {
		if (closeables == null)
			return false;
		boolean result = false;
		for (var closeable : closeables) {
			if (closeable == null)
				continue;
			try {
				closeable.close();
				result = true;
			} catch (IOException e) {
				logger.trace("error during close", e);
			}
		}
		return result;
	}

	public static boolean closeAndLogOnError(String message, Throwable error, Closeable... closeables) {
		if (error == null)
			return false;
		TunnelUtils.closeQuietly(closeables);
		if (error instanceof AsynchronousCloseException)
			return true;
		if (error instanceof ClosedChannelException)
			return true;
		logger.error(message, error);
		return true;
	}

	public static boolean isCertificateUnknownError(Throwable error) {
		if (error instanceof SSLHandshakeException) {
			String msg = Optional.ofNullable(error.getMessage()).map(String::toLowerCase).orElse("");
			if (msg.contains("Received fatal alert: certificate_unknown".toLowerCase()))
				return true;
		}
		return false;
	}

	public static String formatSummary(String prepend, Map<String, Object> summaryData) {
		if (prepend == null)
			prepend = "";
		else if (!prepend.isBlank())
			prepend = prepend + " ";
		if (summaryData == null)
			return prepend + "";
		String result = summaryData.entrySet().stream().filter(ent -> ent.getKey() != null && ent.getValue() != null)
				.map(ent -> {
					var valueStr = ent.getValue().toString();
					if (valueStr.isBlank())
						return null;
					return String.format("%s:%s", ent.getKey(), valueStr);
				}).filter(Objects::nonNull).collect(Collectors.joining(" "));
		return prepend + result;
	}

	public static Map<String, Object> getSummary(Channel channel) {
		Map<String, Object> logData = new LinkedHashMap<>();
		if (channel == null)
			return logData;
		if (channel instanceof ServerTlsChannelExt) {
			var sniServerName = ((ServerTlsChannelExt) channel).getSniServerName();
			logData.put("sniServerNameValue", getSNIServerNameValue(sniServerName));
		}
		Optional<SocketChannel> socketChannelOp = Optional.ofNullable(channel).map(v -> {
			if (v instanceof SocketChannel)
				return (SocketChannel) v;
			return null;
		});
		logData.put("remoteAddress", socketChannelOp.map(v -> {
			try {
				return v.getRemoteAddress();
			} catch (IOException e) {
				return null;
			}
		}).map(Object::toString).orElse(null));
		logData.put("localaddress", socketChannelOp.map(v -> {
			try {
				return v.getLocalAddress();
			} catch (IOException e) {
				return null;
			}
		}).map(Object::toString).orElse(null));
		return logData;
	}

	public static Optional<String> getSNIServerNameValue(SNIServerName sniServerName) {
		if (sniServerName == null)
			return Optional.empty();
		String valueStr;
		if (sniServerName instanceof SNIHostName)
			valueStr = ((SNIHostName) sniServerName).getAsciiName();
		else {
			valueStr = sniServerName.toString();
			String token = "value=";
			var index = valueStr.lastIndexOf(token);
			if (index < 0)
				Optional.empty();
			valueStr = valueStr.substring(index + token.length());
		}
		if (valueStr == null || valueStr.isEmpty())
			Optional.empty();
		return Optional.of(valueStr);
	}

	public static <X> boolean lockAdd(ReadWriteLock lock, List<X> list, X value) {
		Objects.requireNonNull(lock);
		Objects.requireNonNull(list);
		if (value == null)
			return false;
		lock.writeLock().lock();
		try {
			if (!list.contains(value))
				return list.add(value);
		} finally {
			lock.writeLock().unlock();
		}
		return false;
	}

	public static <X> boolean lockRemove(ReadWriteLock lock, List<X> list, X value) {
		Objects.requireNonNull(lock);
		Objects.requireNonNull(list);
		if (value == null)
			return false;
		lock.writeLock().lock();
		try {
			return list.remove(value);
		} finally {
			lock.writeLock().unlock();
		}
	}
}
