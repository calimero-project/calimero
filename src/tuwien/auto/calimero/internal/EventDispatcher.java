/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2021, 2022 B. Malinowsky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Linking this library statically or dynamically with other modules is
    making a combined work based on this library. Thus, the terms and
    conditions of the GNU General Public License cover the whole
    combination.

    As a special exception, the copyright holders of this library give you
    permission to link this library with independent modules to produce an
    executable, regardless of the license terms of these independent
    modules, and to copy and distribute the resulting executable under terms
    of your choice, provided that you also meet, for each linked independent
    module, the terms and conditions of the license of that module. An
    independent module is a module which is not derived from or based on
    this library. If you modify this library, you may extend this exception
    to your version of the library, but you are not obligated to do so. If
    you do not wish to do so, delete this exception statement from your
    version.
*/

package tuwien.auto.calimero.internal;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.lang.System.Logger;
import java.lang.annotation.Annotation;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

class EventDispatcher<T extends Annotation> {
	private static final Lookup lookup = MethodHandles.lookup();

	private static final class ListenerMH {
		private final Object listener;
		private final MethodHandle mh;

		ListenerMH(final Object listener, final MethodHandle mh) {
			this.listener = listener;
			this.mh = mh;
		}
	}

	final Map<Class<?>, Set<ListenerMH>> customEvents = new ConcurrentHashMap<>();
	private final Class<T> eventAnnotation;
	private final Logger logger;

	EventDispatcher(final Class<T> eventAnnotation, final Logger logger) {
		this.eventAnnotation = eventAnnotation;
		this.logger = logger;
	}

	void register(final Class<?> eventType) {
		customEvents.put(eventType, ConcurrentHashMap.newKeySet());
	}

	// TODO we currently register events multiple times if method also exists as annotated default method on interface
	void registerCustomEvents(final Object listener) {
		// check default methods on implemented interfaces
		for (final var iface : listener.getClass().getInterfaces())
			for (final var method : iface.getDeclaredMethods())
				inspectMethodForEvent(method, listener);
		// check normal methods on classes
		for (final var method : listener.getClass().getDeclaredMethods())
			inspectMethodForEvent(method, listener);
	}

	void unregisterCustomEvents(final Object listener) {
		for (final var set : customEvents.values()) {
			set.removeIf(lmh -> listener.equals(lmh.listener));
		}
	}

	private void inspectMethodForEvent(final Method method, final Object listener) {
		if (method.getAnnotation(eventAnnotation) == null)
			return;
		final var paramTypes = method.getParameterTypes();
		if (paramTypes.length != 1) {
			logger.log(WARNING, "cannot register {0}: parameter count not 1", method);
			return;
		}
		final var paramType = paramTypes[0];
		if (!customEvents.containsKey(paramType)) {
			logger.log(DEBUG, "unsupported event type {0}", method);
			return;
		}
		try {
			final var privateLookup = MethodHandles.privateLookupIn(listener.getClass(), lookup);
			final var boundMethod = privateLookup.unreflect(method).bindTo(listener);
			customEvents.get(paramType).add(new ListenerMH(listener, boundMethod));
			logger.log(TRACE, "registered {0}", method);
		}
		catch (final Exception e) {
			logger.log(WARNING, "failed to register {0}", method, e);
		}
	}

	void dispatchCustomEvent(final Object event) {
		customEvents.getOrDefault(event.getClass(), Set.of()).forEach(lmh -> {
			try {
				lmh.mh.invoke(event);
			}
			catch (final Throwable e) {
				logger.log(WARNING, "invoking custom event", e);
			}
		});
	}
}
