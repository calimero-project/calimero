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

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import tuwien.auto.calimero.link.LinkEvent;
import tuwien.auto.calimero.log.LogService;

class EventDispatcherTests {

	private final EventDispatcher<?> ed = new EventDispatcher<>(LinkEvent.class,
			LogService.getLogger(EventDispatcherTests.class));

	@Test
	void unregisterCustomEvents() {
		class Event {}
		class AnotherEvent {}

		class MyListener {
			@LinkEvent
			void event1(final Event e) {}

			@LinkEvent
			void event2(final Event e) {}

			@LinkEvent
			void event3(final AnotherEvent e) {}
		}
		final var listener = new MyListener();

		ed.register(Event.class);
		ed.register(AnotherEvent.class);

		ed.registerCustomEvents(listener);
		assertEquals(2, ed.customEvents.size());

		ed.unregisterCustomEvents(listener);

		assertEquals(2, ed.customEvents.size());
		assertEquals(0, ed.customEvents.get(Event.class).size());
		assertEquals(0, ed.customEvents.get(AnotherEvent.class).size());
	}
}
