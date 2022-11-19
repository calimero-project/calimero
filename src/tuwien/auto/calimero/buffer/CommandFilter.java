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

package tuwien.auto.calimero.buffer;

import static java.lang.System.Logger.Level.ERROR;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.Optional;
import java.util.function.Consumer;

import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.buffer.Configuration.NetworkFilter;
import tuwien.auto.calimero.buffer.Configuration.RequestFilter;
import tuwien.auto.calimero.buffer.LDataObjectQueue.QueueItem;
import tuwien.auto.calimero.buffer.cache.Cache;
import tuwien.auto.calimero.buffer.cache.CacheObject;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.datapoint.DatapointModel;
import tuwien.auto.calimero.log.LogService;


/**
 * Predefined filter for filtering KNX messages of command based datapoints into the
 * associated network buffer configuration and handling requests for this kind of
 * messages.
 * <p>
 * This filter implements both {@link Configuration.NetworkFilter} and
 * {@link Configuration.RequestFilter} for command-based datapoint messages.<br>
 * Command based messages are buffered using a {@link LDataObjectQueue} (an object of this
 * type is also expected when the request method or getNextIndication method is invoked).
 *
 * @author B. Malinowsky
 */
public class CommandFilter implements NetworkFilter, RequestFilter
{
	// stores LDataObjectQueues objects
	private final Deque<CacheObject> indicationKeys = new ArrayDeque<>();
	private volatile Consumer<LDataObjectQueue> userListener;
	private final Consumer<LDataObjectQueue> queueFull = queue -> {
		try {
			Optional.ofNullable(userListener).ifPresent(listener -> listener.accept(queue));
		}
		catch (final RuntimeException e) {
			LogService.getLogger("calimero.buffer").log(ERROR, "L-Data queue listener unexpected behavior", e);
		}
	};

	@Override
	public void init(final Configuration c)
	{}

	/**
	 * Sets the specified listener to receive notification of queue events of buffered
	 * queue objects.
	 * <p>
	 * The listener will replace any previously set listener.
	 *
	 * @param l the listener to set, use {@code null} for no listener
	 */
	public void setQueueListener(final Consumer<LDataObjectQueue> l)
	{
		userListener = l;
	}

	/**
	 * Returns whether new indications are available.
	 * <p>
	 *
	 * @return {@code true} if at least one indication is available,
	 *         {@code false} otherwise
	 */
	public boolean hasNewIndication()
	{
		synchronized (indicationKeys) {
			return !indicationKeys.isEmpty();
		}
	}

	/**
	 * Returns the next available indication.
	 * <p>
	 * The items with the cEMI frame indications are returned in FIFO order according the
	 * time they were supplied to the filter and buffered in the first place, i.e., an
	 * earlier accepted frame is returned before a frame accepted at some later time.<br>
	 * Every item is only returned once by this method, after that it is no longer marked
	 * as new and will not cause {@link #hasNewIndication()} to return {@code true}
	 * for it.<br>
	 * If no indication is available, throws {@link java.util.NoSuchElementException}.
	 * <p>
	 * Nevertheless, the queued item might be retrieved directly through the used cache
	 * (which is obtained by {@link Configuration#getCache()}). Whether or not a returned
	 * item is completely consumed from the queue in the cache, i.e., removed from the
	 * cache object, is specified in the {@link LDataObjectQueue} containing
	 * the item at creation time (which is a task of the network filter).
	 * <p>
	 * Note, if the accessed queue in the cache was modified between the time the
	 * indication was added and this method call in such a way, that the original
	 * indication is not available anymore (for example by removal or emptied queue), that
	 * indication might be skipped or an empty QueueItem is returned.
	 *
	 * @return queue item containing cEMI frame indication
	 */
	public QueueItem getNextIndication()
	{
		synchronized (indicationKeys) {
			return ((LDataObjectQueue) indicationKeys.remove()).getItem();
		}
	}

	/**
	 * Returns the next available indication for the specified KNX address.
	 * <p>
	 * See {@link #getNextIndication()} for more details. In contrast to that method, this
	 * method does not throw.
	 */
	@Override
	public CEMILData request(final KNXAddress dst, final Configuration c)
	{
		if (!(dst instanceof GroupAddress))
			return null;
		final DatapointModel<?> m = c.getDatapointModel();
		if (m != null) {
			final Datapoint dp = m.get((GroupAddress) dst);
			if (dp == null || dp.isStateBased())
				return null;
		}
		synchronized (indicationKeys) {
			for (final Iterator<CacheObject> i = indicationKeys.iterator(); i.hasNext();) {
				final CacheObject co = i.next();
				if (co.getKey().equals(dst)) {
					i.remove();
					return ((LDataObjectQueue) co).getItem().getFrame();
				}
			}
		}
		return null;
	}

	/**
	 * Applies command based filter rules on frame.
	 * <p>
	 * Criteria for accept:<br>
	 * <ul>
	 * <li>the KNX message destination address is a group address</li>
	 * <li>there is <b>no</b> datapoint model available in the configuration, or</li>
	 * <li>there is a datapoint model available with a datapoint identified by the
	 * destination address <b>and</b> the datapoint is command based</li>
	 * <li>the message is an application layer group write or group response</li>
	 * </ul>
	 * On acceptance, the frame is stored into the configuration cache using a
	 * {@link LDataObjectQueue} with consuming read behavior and a maximum queue size of
	 * 10 items.<br>
	 * For uniform handling an accepted frame is always buffered with the L-data
	 * indication message code.
	 *
	 * @param frame {@inheritDoc}
	 * @param c {@inheritDoc}
	 */
	@Override
	public void accept(final CEMI frame, final Configuration c)
	{
		final Cache cache = c.getCache();
		if (cache == null || !(frame instanceof CEMILData))
			return;
		final CEMILData f = (CEMILData) frame;
		if (!(f.getDestination() instanceof GroupAddress))
			return;
		final GroupAddress dst = (GroupAddress) f.getDestination();
		// check if we have a datapoint model, whether it contains the address,
		// and datapoint is command based
		final DatapointModel<?> m = c.getDatapointModel();
		if (m != null) {
			final Datapoint dp = m.get(dst);
			if (dp == null || dp.isStateBased())
				return;
		}
		final byte[] d = f.getPayload();
		// filter for A-Group.write (0x80) and A-Group.res (0x40) services
		final int svc = d[0] & 0x03 | d[1] & 0xC0;
		if (svc != 0x40 && svc != 0x80)
			return;
		final CEMILData copy;
		try {
			copy = (CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_IND, d, f);
		}
		catch (final KNXFormatException e) {
			LogService.getLogger("calimero").log(ERROR, "create L_Data.ind for network buffer: {0}", f, e);
			return;
		}
		CacheObject co = cache.get(dst);
		if (co == null)
			co = new LDataObjectQueue(dst, true, 10, false, queueFull);
		cache.put(co);
		synchronized (indicationKeys) {
			indicationKeys.add(co);
		}
		// this might invoke queue listener, so do it after put and add
		((LDataObjectQueue) co).setFrame(copy);
	}
}
