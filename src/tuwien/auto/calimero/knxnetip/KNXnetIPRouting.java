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

package tuwien.auto.calimero.knxnetip;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static tuwien.auto.calimero.knxnetip.KNXnetIPConnection.BlockingMode.NonBlocking;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.System.Logger.Level;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXListener;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.internal.Executor;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.RoutingBusy;
import tuwien.auto.calimero.knxnetip.servicetype.RoutingIndication;
import tuwien.auto.calimero.knxnetip.servicetype.RoutingLostMessage;
import tuwien.auto.calimero.knxnetip.servicetype.RoutingSystemBroadcast;
import tuwien.auto.calimero.knxnetip.servicetype.SearchRequest;
import tuwien.auto.calimero.knxnetip.servicetype.SearchResponse;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.log.LogService;

/**
 * KNXnet/IP connection using the KNXnet/IP routing protocol.
 * <p>
 * A KNXnet/IP router is a fast replacement for line/backbone couplers and connected main/backbone lines, using Ethernet
 * cabling for example.<br>
 * The router use point to multipoint communication (multicast). By default, routers are joined to the
 * {@link KNXnetIPRouting#DEFAULT_MULTICAST} multicast group. On more KNX installations in one IP network, different
 * multicast addresses have to be assigned.<br>
 * All IP datagrams use UDP port number 3671, and only datagrams on this port are observed. KNXnet/IP Routing always
 * listens on the system setup multicast group for IP system broadcasts.<br>
 * The routing protocol is an unconfirmed service.
 * <p>
 * Optionally, a listener of type {@link RoutingListener} can be supplied to {@link #addConnectionListener(KNXListener)}
 * instead of a default {@link KNXListener}, to receive {@link RoutingListener#lostMessage(LostMessageEvent)}
 * notifications.
 * <p>
 * Multicast considerations:<br>
 * The multicast loopback behavior defines whether multicast datagrams are looped back to the local socket, see
 * {@link MulticastSocket#setLoopbackMode(boolean)}. By default, the loopback mode of the multicast socket used for
 * sending multicast datagrams is enabled. This behavior can be changed by using a KNXnetIPRouting sub type and
 * initializing it by calling {@link #init(NetworkInterface, boolean, boolean)}.
 * <p>
 * A multicast datagram sent with an initial hop count greater 1 may be delivered to the sending host on a different
 * interface (than the sending one), if the host is a member of the multicast group on that interface. The loopback mode
 * setting of the sender's socket has no effect on this behavior.
 *
 * @author B. Malinowsky
 */
public class KNXnetIPRouting extends ConnectionBase
{
	static final int MaxDatagramsPerSecond = 50;

	/**
	 * Multicast address assigned by default to KNXnet/IP routers, address {@value
	 * #DEFAULT_MULTICAST}.
	 * <p>
	 * This is the standard system setup multicast address used in KNXnet/IP.
	 */
	public static final String DEFAULT_MULTICAST = Discoverer.SEARCH_MULTICAST;

	/**
	 * Address of the default multicast group assigned to KNX IP routers.
	 */
	public static final InetAddress DefaultMulticast = Discoverer.SYSTEM_SETUP_MULTICAST;

	private static final InetAddress systemBroadcast = Discoverer.SYSTEM_SETUP_MULTICAST;

	// newer Gira servers have a "reliable communication" option, which uses the
	// following unsupported service type; not part of the knx spec
	private static final int GiraUnsupportedSvcType = 0x538;
	// we will only warn about it once, to avoid spamming the log
	private boolean loggedGiraUnsupportedSvcType;

	private final InetAddress multicast;

	private DatagramChannel dc;
	private DatagramChannel dcSysBcast;

	private volatile boolean loopbackEnabled;
	// This list is used for multicast packets that are looped back in loopback mode. If loopback
	// mode is enabled, sent packets are buffered, and subsequently discarded when received again
	// shortly after (and also removed from this buffer again).
	// This list holds cEMI frames, but basically only the byte array representations are required.
	private final List<CEMILData> loopbackFrames = new ArrayList<>();
	private static final int maxLoopbackQueueSize = 20;

	private volatile BiFunction<KNXnetIPHeader, ByteBuffer, SearchResponse> searchRequestCallback;

	// KNX IP routing busy flow control

	private static final Duration randomWaitScale = Duration.ofMillis(50);
	private static final Duration throttleScale = Duration.ofMillis(100);
	private Instant currentWaitUntil = Instant.EPOCH;
	private volatile Instant pauseSendingUntil = Instant.EPOCH;
	private volatile Instant throttleUntil = Instant.EPOCH;
	private Instant lastRoutingBusy = Instant.EPOCH;
	private final AtomicInteger routingBusyCounter = new AtomicInteger();
	private volatile Future<?> decrementBusyCounter = CompletableFuture.completedFuture(null);

	private long datagramCount;
	private long countStart = System.nanoTime();

	private long lastTx;


	/**
	 * Creates a new KNXnet/IP routing service.
	 * <p>
	 * In general, routers are assigned a multicast address by adding an offset to the
	 * system setup multicast address ({@value #DEFAULT_MULTICAST}) for each KNX
	 * installation, by default this offset is 0 (i.e., only one used installation).
	 *
	 * @param netIf specifies the local network interface used to send outgoing multicast datagrams,
	 *        and join the multicast group to receive multicast datagrams,
	 *        use {@code null} for the default interface;
	 * @param mcGroup IP multicast address specifying the multicast group this connection shall join,
	 *        use {@link #DefaultMulticast} for the default multicast group;
	 *        value of {@code mcGroup ≥ }{@value #DEFAULT_MULTICAST}
	 * @throws KNXException on socket error, or if joining the multicast group failed
	 */
	public KNXnetIPRouting(final NetworkInterface netIf, final InetAddress mcGroup) throws KNXException
	{
		this(mcGroup);
		init(netIf, true, true);
	}

	/**
	 * Use this constructor in case initialization is called separately at a later point
	 * (using {@link #init(NetworkInterface, boolean, boolean)}).
	 *
	 * @param mcGroup see {@link #KNXnetIPRouting(NetworkInterface, InetAddress)}
	 */
	protected KNXnetIPRouting(final InetAddress mcGroup)
	{
		super(KNXnetIPHeader.ROUTING_IND, 0, 1, 0);
		if (mcGroup == null)
			multicast = DefaultMulticast;
		else if (!isValidRoutingMulticast(mcGroup))
			throw new KNXIllegalArgumentException("non-valid routing multicast " + mcGroup);
		else
			multicast = mcGroup;
	}

	/**
	 * Sends a cEMI frame to the joined multicast group.
	 *
	 * @param frame cEMI message to send
	 * @param mode arbitrary value, does not influence behavior, since routing is always a
	 *        unconfirmed, nonblocking service
	 */
	@Override
	public void send(final CEMI frame, final BlockingMode mode) throws KNXConnectionClosedException
	{
		if (frame.getMessageCode() != CEMILData.MC_LDATA_IND)
			throw new KNXIllegalArgumentException("cEMI frame is not an L-Data.ind");
		try {
			if (loopbackEnabled) {
				synchronized (loopbackFrames) {
					loopbackFrames.add((CEMILData) frame);
				}
				logger.log(TRACE, "add to multicast loopback frame buffer: {0}", frame);
			}
			checkLastTx();
			// filter IP system broadcasts and always send them unsecured
			if (RoutingSystemBroadcast.validSystemBroadcast(frame)) {
				final var buf = ByteBuffer.wrap(PacketHelper.toPacket(new RoutingSystemBroadcast(frame)));
				final InetSocketAddress dst = new InetSocketAddress(systemBroadcast, DEFAULT_PORT);
				enforceDatagramRateLimit();
				logger.log(TRACE, "sending cEMI frame, SBC {0} {1}", NonBlocking, DataUnitBuilder.toHex(buf.array(), " "));
				if (dcSysBcast != null)
					dcSysBcast.send(buf, dst);
				else
					dc.send(buf, dst);
			}
			else {
				applyRoutingFlowControl();
				super.send(frame, NonBlocking);
			}

			// we always succeed...
			setState(OK);
		}
		catch (final IOException e) {
			close(CloseEvent.INTERNAL, "communication failure", ERROR, e);
			throw new KNXConnectionClosedException("connection closed (" + e.getMessage() + ")");
		}
		catch (final KNXTimeoutException ignore) {}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	public final void send(final RoutingBusy busy) throws KNXConnectionClosedException
	{
		send(PacketHelper.toPacket(busy));
	}

	@Override
	public String name()
	{
		return "KNXnet/IP Routing " + super.name();
	}

	/**
	 * Sets the default hop count (TTL) used in the IP header of encapsulated cEMI
	 * messages.
	 * <p>
	 * This value is used to limit the multicast geographically, although this is just a
	 * rough estimation. The hop count value is forwarded to the underlying multicast
	 * socket used for communication.
	 *
	 * @param hopCount hop count value, 0 &lt;= value &lt;= 255
	 */
	public final void setHopCount(final int hopCount)
	{
		if (hopCount < 0 || hopCount > 255)
			throw new KNXIllegalArgumentException("hop count out of range");
		try {
			dc.setOption(StandardSocketOptions.IP_MULTICAST_TTL, hopCount);
		}
		catch (final IOException e) {
			logger.log(ERROR, "failed to set hop count", e);
		}
	}

	/**
	 * Returns the current hop count (time-to-live) used in the IP header of encapsulated cEMI messages when
	 * sending multicast datagrams.
	 *
	 * @return hop count in the range 0 to 255
	 */
	public final int getHopCount()
	{
		try {
			return dc.getOption(StandardSocketOptions.IP_MULTICAST_TTL);
		}
		catch (final IOException e) {
			logger.log(ERROR, "failed to get hop count", e);
		}
		return 1;
	}

	public final NetworkInterface networkInterface() {
		try {
			final NetworkInterface netif = dc.getOption(StandardSocketOptions.IP_MULTICAST_IF);
			return netif == null ? Net.defaultNetif : netif;
		}
		catch (final IOException e) {
			throw new KnxRuntimeException("socket error getting network interface", e);
		}
	}

	/**
	 * Returns whether this KNXnet/IP routing instance has local loopback of KNXnet/IP
	 * routing multicast datagrams enabled or not.
	 *
	 * @return {@code true} if loopback is used, {@code false} otherwise
	 */
	public final boolean usesMulticastLoopback()
	{
		try {
			return dc.getOption(StandardSocketOptions.IP_MULTICAST_LOOP);
		}
		catch (final IOException e) {
			// if we can't access loopback mode, we assume that we also couldn't set it
			// during initialization; therefore, return socket defaults
			return true;
		}
	}

	/**
	 * Checks whether the supplied IP address is a valid KNX routing multicast address.
	 *
	 * @param address the IP address to check
	 * @return {@code true} if address qualifies as KNX multicast, {@code false} otherwise
	 */
	public static boolean isValidRoutingMulticast(final InetAddress address)
	{
		return address != null && address.isMulticastAddress()
				&& toLong(address) >= toLong(DefaultMulticast);
	}

	/**
	 * Initialization routine to set the multicast network interface, loopback behavior
	 * and receiver loop.
	 * <p>
	 * Call this method only once during initialization.
	 *
	 * @param netIf see {@link #KNXnetIPRouting(NetworkInterface, InetAddress)}
	 * @param useMulticastLoopback {@code true} to loopback multicast packets to the
	 *        local socket, {@code false} otherwise; this parameter is only
	 *        interpreted as a hint by the operating system
	 * @param startReceiver {@code true} to start a threaded receiver loop which
	 *        dispatches to
	 *        {@link #handleServiceType(KNXnetIPHeader, byte[], int, InetAddress, int)},
	 *        {@code false} if received socket datagrams are handled by other means
	 * @throws KNXException on failed creation or initialization of multicast socket
	 */
	protected void init(final NetworkInterface netIf, final boolean useMulticastLoopback,
		final boolean startReceiver) throws KNXException
	{
		ctrlEndpt = new InetSocketAddress(multicast, DEFAULT_PORT);
		dataEndpt = ctrlEndpt;
		logger = LogService.getLogger("calimero.knxnetip." + name());

		try {
			dc = newChannel();
			dcSysBcast = !multicast.equals(systemBroadcast) ? newChannel() : null;

			var setNetif = netIf;
			if (setNetif != null) {
				dc.setOption(StandardSocketOptions.IP_MULTICAST_IF, setNetif);
				if (dcSysBcast != null)
					dcSysBcast.setOption(StandardSocketOptions.IP_MULTICAST_IF, setNetif);
			}
			else
				setNetif = Net.defaultNetif;

			logger.log(DEBUG, "join multicast group {0} on {1}", multicast.getHostAddress(), setNetif.getName());
			dc.join(multicast, setNetif);
			if (dcSysBcast != null)
				dcSysBcast.join(systemBroadcast, setNetif);

			// socket is unused
			socket = dc.socket();

			dc.setOption(StandardSocketOptions.IP_MULTICAST_LOOP, useMulticastLoopback);
			if (dcSysBcast != null)
				dcSysBcast.setOption(StandardSocketOptions.IP_MULTICAST_LOOP, useMulticastLoopback);
			loopbackEnabled = usesMulticastLoopback();
			logger.log(INFO, "multicast loopback mode " + (loopbackEnabled ? "enabled" : "disabled"));
		}
		catch (final IOException e) {
			closeSilently(dc, e);
			closeSilently(dcSysBcast, e);
			throw new KNXException(
					"initializing multicast (group " + multicast.getHostAddress() + "): " + e.getMessage(), e);
		}

		if (startReceiver)
			startChannelReceiver(new ChannelReceiver(this, dc), "KNXnet/IP receiver");
		if (dcSysBcast != null) {
			final var sysBcastLooper = new ChannelReceiver(this, dcSysBcast) {
				@Override
				protected void onReceive(final InetSocketAddress source, final byte[] data, final int offset,
						final int length) {
					try {
						final KNXnetIPHeader h = new KNXnetIPHeader(data, offset);
						if (h.getTotalLength() > length)
							logger.log(WARNING, "received frame length " + length + " for " + h + " - ignored");
						else if (h.getVersion() != KNXNETIP_VERSION_10)
							close(CloseEvent.INTERNAL, "protocol version changed", ERROR, null);
						else if (h.getServiceType() == KNXnetIPHeader.SEARCH_REQ
								|| h.getServiceType() == KNXnetIPHeader.SearchRequest)
							searchRequest(source, h, data, offset + h.getStructLength());
						else
							systemBroadcast(h, data, offset + h.getStructLength());
					}
					catch (KNXFormatException | IOException | RuntimeException e) {
						logger.log(WARNING, "received invalid frame", e);
					}
				}
			};
			startChannelReceiver(sysBcastLooper, "KNX IP system broadcast receiver");
		}
		setState(OK);
	}

	private static DatagramChannel newChannel() throws IOException {
		return DatagramChannel.open(StandardProtocolFamily.INET)
				.setOption(StandardSocketOptions.SO_REUSEADDR, true)
				.bind(new InetSocketAddress(DEFAULT_PORT))
				.setOption(StandardSocketOptions.IP_MULTICAST_TTL, 64);
	}

	private void startChannelReceiver(final ReceiverLoop looper, final String name) {
		Executor.execute(looper, name);
	}

	private static class ChannelReceiver extends ReceiverLoop {
		private final DatagramChannel dc;

		ChannelReceiver(final KNXnetIPRouting r, final DatagramChannel dc) {
			super(r, null, 0x200, 0, 0);
			this.dc = dc;
		}

		@Override
		protected void setTimeout(final int timeout) {}

		@Override
		protected void receive(final byte[] buf) throws IOException {
			final ByteBuffer buffer = ByteBuffer.wrap(buf);
			final var source = dc.receive(buffer);
			buffer.flip();
			onReceive((InetSocketAddress) source, buf, buffer.position(), buffer.remaining());
		}
	}

	protected DatagramChannel channel() { return dc; }

	@Override
	protected boolean handleServiceType(final KNXnetIPHeader h, final byte[] data,
			final int offset, final InetAddress src, final int port) throws KNXFormatException, IOException {
		final int svc = h.getServiceType();
		if (h.getVersion() != KNXNETIP_VERSION_10)
			close(CloseEvent.INTERNAL, "protocol version changed", ERROR, null);
		else if (svc == KNXnetIPHeader.ROUTING_IND) {
			final RoutingIndication ind = new RoutingIndication(data, offset, h.getTotalLength()
					- h.getStructLength());
			final CEMI frame = ind.getCEMI();
			if (discardLoopbackFrame(frame))
				return true;
			fireFrameReceived(frame);
		}
		else if (svc == KNXnetIPHeader.ROUTING_LOST_MSG) {
			final RoutingLostMessage lost = new RoutingLostMessage(data, offset);
			fireLostMessage(new InetSocketAddress(src, port), lost);
		}
		else if (svc == KNXnetIPHeader.ROUTING_BUSY) {
			final RoutingBusy busy = new RoutingBusy(data, offset);
			updateRoutingFlowControl(busy, new InetSocketAddress(src, port));

			fireRoutingBusy(new InetSocketAddress(src, port), busy);
		}
		else if (svc == KNXnetIPHeader.RoutingSystemBroadcast && multicast.equals(systemBroadcast)) {
			return systemBroadcast(h, data, offset);
		}
		else if (svc == KNXnetIPHeader.SEARCH_REQ || svc == KNXnetIPHeader.SearchRequest)
			searchRequest(new InetSocketAddress(src, port), h, data, offset);
		else if (svc == GiraUnsupportedSvcType) {
			if (!loggedGiraUnsupportedSvcType)
				logger.log(WARNING, "received unsupported Gira-specific service type 0x538, will be silently ignored: {0}",
						DataUnitBuilder.toHex(data, " "));
			loggedGiraUnsupportedSvcType = true;
		}
		// skip multicast packets from searches & secure services, to avoid logged warnings about unknown frames
		else if (!h.isSecure() && svc != KNXnetIPHeader.SEARCH_RES && svc != KNXnetIPHeader.SearchResponse)
			return super.handleServiceType(h, data, offset, src, port);
		return true;
	}

	private void searchRequest(final InetSocketAddress source, final KNXnetIPHeader h, final byte[] data,
			final int offset) throws KNXFormatException, IOException {
		final var callback = searchRequestCallback;
		if (callback == null)
			return;
		final HPAI endpoint = SearchRequest.from(h, data, offset).getEndpoint();
		if (endpoint.getHostProtocol() != HPAI.IPV4_UDP) {
			logger.log(WARNING, "KNX IP has protocol support for UDP/IP only");
			return;
		}
		final var response = callback.apply(h, ByteBuffer.wrap(data).position(offset));
		if (response != null) {
			@SuppressWarnings("resource")
			final var channel = dcSysBcast != null ? dcSysBcast : dc;
			channel.send(ByteBuffer.wrap(PacketHelper.toPacket(response)), createResponseAddress(endpoint, source));
		}
	}

	private static InetSocketAddress createResponseAddress(final HPAI endpoint, final InetSocketAddress sender) {
		// NAT: if the data EP is incomplete or left empty, we fall back to the IP address and port of the sender.
		if (endpoint.getAddress().isAnyLocalAddress() || endpoint.getPort() == 0)
			return sender;
		return new InetSocketAddress(endpoint.getAddress(), endpoint.getPort());
	}

	@Override
	protected void close(final int initiator, final String reason, final Level level, final Throwable t) {
		synchronized (this) {
			if (closing > 0)
				return;
			closing = 1;
		}

		logger.log(level, "close connection - " + reason, t);

		closeSilently(dc, null);
		closeSilently(dcSysBcast, null);

		cleanup(initiator, reason, level, t);
	}

	private static void closeSilently(final DatagramChannel dc, final Exception e) {
		try {
			if (dc != null)
				dc.close();
		}
		catch (final IOException ioe) {
			if (e != null)
				e.addSuppressed(ioe);
		}
	}

	protected void send(final byte[] packet) throws KNXConnectionClosedException
	{
		final int state = getState();
		if (state == CLOSED) {
			logger.log(WARNING, "send invoked on closed connection - aborted");
			throw new KNXConnectionClosedException("connection closed");
		}
		if (state < 0) {
			logger.log(ERROR, "send invoked in error state " + state + " - aborted");
			throw new IllegalStateException("in error state, send aborted");
		}
		try {
			send(packet, dataEndpt);
			setState(OK);
		}
		catch (final InterruptedIOException e) {
			close(CloseEvent.USER_REQUEST, "interrupted", WARNING, e);
			Thread.currentThread().interrupt();
			throw new KNXConnectionClosedException("interrupted connection got closed");
		}
		catch (final IOException e) {
			close(CloseEvent.INTERNAL, "communication failure", ERROR, e);
			throw new KNXConnectionClosedException("connection closed");
		}
	}

	@Override
	protected void send(final byte[] packet, final InetSocketAddress dst) throws IOException {
		dc.send(ByteBuffer.wrap(packet), dst);
	}

	private boolean systemBroadcast(final KNXnetIPHeader h, final byte[] data, final int offset)
			throws KNXFormatException {

		final int svc = h.getServiceType();
		if (svc == KNXnetIPHeader.RoutingSystemBroadcast) {
			final RoutingSystemBroadcast ind = new RoutingSystemBroadcast(data, offset,
					h.getTotalLength() - h.getStructLength());
			final CEMI frame = ind.cemi();
			if (discardLoopbackFrame(frame))
				return true;
			final FrameEvent fe = new FrameEvent(this, frame, true);
			listeners.fire(l -> l.frameReceived(fe));
			return true;
		}
		return false;
	}

	private void fireLostMessage(final InetSocketAddress sender, final RoutingLostMessage lost)
	{
		final LostMessageEvent e = new LostMessageEvent(this, sender, lost.getDeviceState(), lost.getLostMessages());
		listeners.fire(l -> {
			if (l instanceof RoutingListener)
				((RoutingListener) l).lostMessage(e);
		});
	}

	private void fireRoutingBusy(final InetSocketAddress sender, final RoutingBusy busy)
	{
		final RoutingBusyEvent e = new RoutingBusyEvent(this, sender, busy);
		listeners.fire(l -> {
			if (l instanceof RoutingListener)
				((RoutingListener) l).routingBusy(e);
		});
	}

	private void fireRateLimit() {
		final var e = new RateLimitEvent(this);
		listeners.fire(l -> {
			if (l instanceof RoutingListener)
				((RoutingListener) l).rateLimit(e);
		});
	}

	private boolean discardLoopbackFrame(final CEMI frame)
	{
		if (!loopbackEnabled)
			return false;
		final byte[] a = frame.toByteArray();
		synchronized (loopbackFrames) {
			for (final Iterator<CEMILData> i = loopbackFrames.iterator(); i.hasNext();) {
				if (Arrays.equals(a, i.next().toByteArray())) {
					i.remove();
					logger.log(TRACE, "discard multicast loopback cEMI frame: {0}", frame);
					return true;
				}
				// remove oldest entry if exceeding max. loopback queue size
				if (loopbackFrames.size() > maxLoopbackQueueSize)
					i.remove();
			}
		}
		return false;
	}

	private void checkLastTx() throws InterruptedException {
		lock.lock();
		try {
			final long now = System.nanoTime();
			final long diff = now - lastTx;
			if (diff < 5_000_000) {
				final long millis = Math.round((5_000_000 - diff) / 1_000_000d);
				Thread.sleep(millis);
			}
			lastTx = now;
		}
		finally {
			lock.unlock();
		}
	}

	private void updateRoutingFlowControl(final RoutingBusy busy, final InetSocketAddress sender) {
		// in case we sent the routing busy notification, ignore it
		if (sentByUs(sender))
			return;

		// setup timing for routing busy flow control
		final Instant now = Instant.now();
		final Instant waitUntil = now.plus(busy.waitTime());
		Level level = TRACE;
		boolean update = false;
		if (waitUntil.isAfter(currentWaitUntil)) {
			currentWaitUntil = waitUntil;
			level = DEBUG;
			update = true;
		}
		logger.log(level, "device {0} sent {1}", Net.hostPort(sender), busy);

		// increment random wait scaling iff >= 10 ms have passed since the last counted routing busy
		if (now.isAfter(lastRoutingBusy.plusMillis(10))) {
			lastRoutingBusy = now;
			routingBusyCounter.incrementAndGet();
			update = true;
		}

		if (!update)
			return;

		final double rand = Math.random();
		final long randomWait = Math.round(rand * routingBusyCounter.get() * randomWaitScale.toMillis());

		// invariant on instants: throttle >= pause sending >= current wait
		pauseSendingUntil = currentWaitUntil.plusMillis(randomWait);
		final long throttle = routingBusyCounter.get() * throttleScale.toMillis();
		throttleUntil = pauseSendingUntil.plusMillis(throttle);

		final long continueIn = Duration.between(now, pauseSendingUntil).toMillis();
		logger.log(DEBUG, "set routing busy counter = {0}, random wait = {1} ms, continue sending in {2} ms, throttle {3} ms",
				routingBusyCounter, randomWait, continueIn, throttle);

		final long initialDelay = Duration.between(now, throttleUntil).toMillis() + 5;
		decrementBusyCounter.cancel(false);
		decrementBusyCounter = Executor.scheduledExecutor().scheduleAtFixedRate(this::decrementBusyCounter,
				initialDelay, 5, TimeUnit.MILLISECONDS);
	}

	private boolean sentByUs(final InetSocketAddress sender) {
		final var netif = networkInterface();
		if (netif == Net.defaultNetif) {
			// check addresses of all netifs, in case no outgoing mcast netif was configured
			try {
				return NetworkInterface.networkInterfaces().flatMap(NetworkInterface::inetAddresses)
						.anyMatch(sender.getAddress()::equals);
			}
			catch (final SocketException e) {}
		}

		// this will give a false positive if we and sending device use the same local netif
		return netif.inetAddresses().anyMatch(sender.getAddress()::equals);
	}

	private void decrementBusyCounter() {
		// decrement iff counter > 0, otherwise cancel decrementing
		if (routingBusyCounter.accumulateAndGet(0, (v, u) -> v > 0 ? --v : v) == 0)
			decrementBusyCounter.cancel(false);
	}

	// check whether we have to slow down or pause sending due to routing flow control
	private void applyRoutingFlowControl() throws InterruptedException {
		enforceDatagramRateLimit();

		if (routingBusyCounter.get() == 0)
			return;

		// we have to loop because a new arrival of routing busy might update timings
		while (true) {
			final Instant now = Instant.now();
			final long sleep = Duration.between(now, pauseSendingUntil).toMillis();
			if (sleep > 0) {
				logger.log(DEBUG, "applying routing flow control for {0}, wait {1} ms ...",
						getRemoteAddress().getAddress().getHostAddress(), sleep);
				Thread.sleep(sleep);
			}
			else if (now.isBefore(throttleUntil)) {
				Thread.sleep(5);
				break;
			}
			else
				break;
		}
	}

	private void enforceDatagramRateLimit() throws InterruptedException {
		lock.lock();
		try {
			final long now = System.nanoTime();
			final long diff = now - countStart;
			if (diff >= 1_000_000_000) {
				countStart = now;
				datagramCount = 1;
				return;
			}
			if (++datagramCount > MaxDatagramsPerSecond) {
				final long remaining = 1_000 - diff / 1_000_000;
				if (remaining > 0) {
					fireRateLimit();
					logger.log(DEBUG, "reached max. datagrams/second, wait {0} ms ...", remaining);
					Thread.sleep(remaining);
				}
			}
		}
		finally {
			lock.unlock();
		}
	}

	private static long toLong(final InetAddress addr)
	{
		// we assume 4 byte Internet address for multicast
		final byte[] buf = addr.getAddress();
		long ret = buf[3] & 0xffL;
		ret |= (buf[2] << 8) & 0xff00L;
		ret |= (buf[1] << 16) & 0xff0000L;
		ret |= (buf[0] << 24) & 0xff000000L;
		return ret;
	}
}
