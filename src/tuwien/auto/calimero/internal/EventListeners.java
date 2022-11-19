/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2006, 2022 B. Malinowsky

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

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.lang.annotation.Annotation;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

import tuwien.auto.calimero.log.LogService;


/**
 * Container for keeping event listeners.
 * <p>
 * The assumption for implementation of this class is that iterating over event listeners is the predominant operation,
 * adding and removing listeners not.
 *
 * @author B. Malinowsky
 */
public class EventListeners<T>
{
	private final CopyOnWriteArrayList<T> listeners = new CopyOnWriteArrayList<>();
	private final Logger logger;
	private final EventDispatcher<?> customEvents;

	/**
	 * Creates a new event listeners container object.
	 *
	 * @param logger optional logger for log output
	 */
	public EventListeners(final Logger logger)
	{
		this.logger = logger;
		customEvents = new EventDispatcher<>(Annotation.class, logger);
	}

	public EventListeners(final Logger logger, final Class<? extends Annotation> eventAnnotation)
	{
		this.logger = logger;
		customEvents = new EventDispatcher<>(eventAnnotation, logger);
	}

	/**
	 * Creates a new event listeners container object.
	 */
	public EventListeners()
	{
		this(LogService.getLogger("calimero"));
	}

	/**
	 * Adds the specified event listener {@code l} to this container.
	 * <p>
	 * If {@code l} was already added as listener, no action is performed.
	 *
	 * @param l the listener to add
	 */
	public synchronized void add(final T l)
	{
		if (listeners.addIfAbsent(l))
			customEvents.registerCustomEvents(l);
	}

	/**
	 * Removes the specified event listener {@code l} from this container.
	 * <p>
	 * If {@code l} was not added in the first place, no action is performed.
	 *
	 * @param l the listener to remove
	 */
	public synchronized void remove(final T l)
	{
		if (listeners.remove(l))
			customEvents.unregisterCustomEvents(l);
	}

	/**
	 * Removes all event listeners from this container.
	 */
	public void removeAll()
	{
		listeners.clear();
	}

	/**
	 * Returns a list of all event listeners. Trying to modify the returned list will have no impact on the event
	 * listeners kept by this container. It might also fail if the returned list is unmodifiable.
	 *
	 * @return list of all event listeners in this container, with list size equal to the number of currently maintained
	 *         listeners
	 */
	public List<T> listeners()
	{
		return Collections.unmodifiableList(listeners);
	}

	public void fire(final Consumer<? super T> c)
	{
		for (final T l : listeners) {
			try {
				c.accept(l);
			}
			catch (final RuntimeException rte) {
				remove(l);
				logger.log(Level.ERROR, "removed event listener", rte);
			}
		}
	}

	public void registerEventType(final Class<?> eventType) {
		customEvents.register(eventType);
	}

	public void dispatchCustomEvent(final Object event) {
		customEvents.dispatchCustomEvent(event);
	}
}
