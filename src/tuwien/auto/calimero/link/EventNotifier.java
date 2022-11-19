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

package tuwien.auto.calimero.link;

import java.lang.System.Logger;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.function.Consumer;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.KNXListener;
import tuwien.auto.calimero.internal.EventListeners;

/**
 * Threaded event notifier for network link and monitor.
 *
 * @author B. Malinowsky
 */
public abstract class EventNotifier<T extends LinkListener> extends Thread implements KNXListener
{
	final Logger logger;
	final Object source;

	private final EventListeners<T> listeners;

	private final Deque<Consumer<? super T>> events = new ArrayDeque<>();
	private volatile boolean running = true;

	EventNotifier(final Object source, final Logger logger)
	{
		super("Calimero link notifier");
		this.logger = logger;
		this.source = source;
		listeners = new EventListeners<>(logger, LinkEvent.class);
		setDaemon(true);
	}

	@Override
	public final void run()
	{
		try {
			while (running) {
				final Consumer<? super T> c;
				synchronized (events) {
					while (events.isEmpty())
						events.wait();
					c = events.remove();
				}
				if (c instanceof CustomEventConsumer)
					fireCustomEvent(c);
				else
					fire(c);
			}
		}
		catch (final InterruptedException e) {}
		finally {
			drainEvents();
		}
	}

	private void drainEvents() {
		while (true) {
			final Consumer<? super T> c;
			synchronized (events) {
				if (events.isEmpty())
					return;
				c = events.remove();
			}
			fire(c);
		}
	}

	@Override
	public abstract void frameReceived(FrameEvent e);

	@Override
	public void connectionClosed(final CloseEvent e)
	{
		addEvent(l -> l.linkClosed(new CloseEvent(source, e.getInitiator(), e.getReason())));
		quit();
	}

	public EventListeners<T> getListeners()
	{
		return listeners;
	}

	public void registerEventType(final Class<?> eventType) {
		listeners.registerEventType(eventType);
	}

	private interface CustomEventConsumer<T> extends Consumer<T> {}

	public void dispatchCustomEvent(final Object event) {
		final CustomEventConsumer<T> cec = __ -> listeners.dispatchCustomEvent(event);
		addEvent(cec);
	}

	final void addEvent(final Consumer<? super T> c)
	{
		synchronized (events) {
			events.add(c);
			events.notify();
		}
	}

	final void addListener(final T l)
	{
		listeners.add(l);
	}

	final void removeListener(final T l)
	{
		listeners.remove(l);
	}

	final void quit()
	{
		running = false;
		interrupt();
		if (currentThread() != this) {
			try {
				join();
			}
			catch (final InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}

	private void fire(final Consumer<? super T> c)
	{
		 listeners.fire(c);
	}

	private void fireCustomEvent(final Consumer<? super T> c) { c.accept(null); }
}
