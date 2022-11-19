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
import static tuwien.auto.calimero.knxnetip.Net.hostPort;
import static tuwien.auto.calimero.knxnetip.util.Srp.withDeviceDescription;

import java.io.IOException;
import java.lang.System.Logger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXInvalidResponseException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.internal.Executor;
import tuwien.auto.calimero.internal.UdpSocketLooper;
import tuwien.auto.calimero.knxnetip.TcpConnection.SecureSession;
import tuwien.auto.calimero.knxnetip.servicetype.DescriptionRequest;
import tuwien.auto.calimero.knxnetip.servicetype.DescriptionResponse;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.SearchRequest;
import tuwien.auto.calimero.knxnetip.servicetype.SearchResponse;
import tuwien.auto.calimero.knxnetip.util.DIB;
import tuwien.auto.calimero.knxnetip.util.Srp;
import tuwien.auto.calimero.log.LogService;

/**
 * Does KNXnet/IP discovery and retrieval of self description from other KNX IP devices.
 * <p>
 * Both searches for server discovery and description requests can be run in blocking mode
 * or asynchronous in the background.
 * Search or self-description requests are sent using UDP or TCP, depending on the created discoverer.<p>
 * This discoverer supports networks with routers doing network address translation (NAT).
 * Due to protocol limitations, only IPv4 addresses are supported when network address
 * translation is <b>not</b> used. With NAT enabled, IPv6 addresses can be used as well.
 * A note on (not) using network address translation (NAT):<br>
 * If discovery or description attempts fail indicating a timeout limit, it might be
 * possible that NAT is used on routers while traversing the network, so the solution
 * would be to enable the use of NAT.
 * On the other hand, if NAT is used but not supported by the answering device, no
 * response is received and a timeout will occur nevertheless.
 * <p>
 * For discovery searches, the default timeout is 10 seconds. An additional option for choosing IP multicast over IP
 * unicast is available in {@link Discoverer#Discoverer(InetAddress, int, boolean, boolean)}. This
 * allows to select, whether search responses by answering servers are sent via multicast
 * and received by the local multicast socket, or if responses are sent via unicast using
 * the local host and port as address for the reply. Using multicast response is of
 * advantage in case KNXnet/IP servers are located in different subnetworks.
 * <p>
 * Cancellation policy on thread interrupts: any running searches are canceled, see
 * {@link #stopSearch()}, blocking invocations of startSearch (i.e., parameter
 * {@code wait = true}) will return (before the specified timeout occurred).
 *
 * @author B. Malinowsky
 */
public class Discoverer
{
	/**
	 * Name of the log service used by a discoverer.
	 */
	public static final String LOG_SERVICE = "calimero.knxnetip.Discoverer";

	/**
	 * Multicast IP address used for discovery, multicast group is {@value}.
	 */
	public static final String SEARCH_MULTICAST = "224.0.23.12";

	/**
	 * Port number used for discovery, port is {@value}.
	 */
	public static final int SEARCH_PORT = KNXnetIPConnection.DEFAULT_PORT;

	private static final Logger logger = LogService.getLogger(LOG_SERVICE);
	static final InetAddress SYSTEM_SETUP_MULTICAST;
	static {
		InetAddress a = null;
		try {
			a = InetAddress.getByName(SEARCH_MULTICAST);
		}
		catch (final UnknownHostException e) {
			logger.log(ERROR, "on resolving system setup multicast " + SEARCH_MULTICAST, e);
		}
		SYSTEM_SETUP_MULTICAST = a;
	}

	// local host/port
	private InetAddress host;
	private final int port;
	// is our discovery/description aware of network address translation
	private final boolean nat;
	// is our search set up for multicast responses
	// for implications on forwarding multicast through NAT inside/outside interfaces,
	// see also RFC 5135
	private final boolean mcast;


	private volatile Duration timeout = Duration.ofSeconds(10);

	private final List<ReceiverLoop> receivers = Collections.synchronizedList(new ArrayList<>());
	private final List<Result<SearchResponse>> responses = Collections.synchronizedList(new ArrayList<>());


	/**
	 * Discoverer result, either containing a {@link SearchResponse} or {@link DescriptionResponse}.
	 */
	public static final class Result<T>
	{
		private final T response;
		private final NetworkInterface ni;
		private final InetSocketAddress local;
		private final InetSocketAddress remote;

		Result(final T r, final NetworkInterface outgoing, final InetSocketAddress local, final InetSocketAddress remote)
		{
			response = r;
			ni = outgoing;
			this.local = local;
			this.remote = remote;
		}

		/**
		 * @return the received discoverer response
		 */
		public T getResponse()
		{
			return response;
		}

		/**
		 * @return the local network interface used for the discovery or description request
		 */
		public NetworkInterface getNetworkInterface()
		{
			return ni;
		}

		/**
		 * @return local endpoint used for the discovery or description request
		 */
		public InetSocketAddress localEndpoint() { return local; }

		/**
		 * @return address of the remote endpoint which sent the response
		 */
		public InetSocketAddress remoteEndpoint() { return remote; }

		@Override
		public String toString() {
			return hostPort(local) + " (" + ni.getName() + ") <- " + response;
		}

		@Override
		public boolean equals(final Object obj)
		{
			if (this == obj)
				return true;
			if (!(obj instanceof Result<?>))
				return false;
			final Result<?> other = (Result<?>) obj;
			return getNetworkInterface().equals(other.getNetworkInterface())
					&& localEndpoint().equals(other.localEndpoint())
					&& getResponse().equals(other.getResponse()) && remote.equals(other.remote);
		}

		@Override
		public int hashCode()
		{
			final int prime = 17;
			return prime * (prime * (prime * getNetworkInterface().hashCode() + localEndpoint().hashCode())
					+ getResponse().hashCode()) + remote.hashCode();
		}
	}

	/**
	 * Returns a discoverer which uses UDP with unicast responses for discovery &amp; description requests.
	 *
	 * @param nat {@code true} to use network address translation (NAT) aware discovery, {@code false} otherwise
	 * @return a discoverer
	 */
	public static Discoverer udp(final boolean nat) {
		return new Discoverer(0, nat);
	}

	/**
	 * Returns a discoverer which uses the supplied TCP connection for discovery &amp; description requests.
	 *
	 * @param c the connection to use, ownership is not transferred to the discoverer
	 * @return a {@link DiscovererTcp} instance
	 */
	public static DiscovererTcp tcp(final TcpConnection c) {
		return new DiscovererTcp(c);
	}

	/**
	 * Returns a discoverer which uses the supplied secure session for discovery &amp; description requests.
	 *
	 * @param session the secure session to use, ownership is not transferred to the discoverer
	 * @return a {@link DiscovererTcp} instance
	 */
	public static DiscovererTcp secure(final SecureSession session) {
		return new DiscovererTcp(session);
	}

	/**
	 * Creates a new Discoverer.
	 * <p>
	 * Network address translation:<br>
	 * If subsequent discovery or description attempts fail indicating a timeout limit, it
	 * might be possible that network address translation (NAT) is used on routers while
	 * traversing the network (besides the other reason that timeouts are too short). This
	 * would effectively stop any communication done in the standard way, due to the way
	 * the HPAI structure is used by default.<br>
	 * Setting the parameter for indicating use of NAT to {@code true} takes account
	 * of such routers, leading to the desired behavior.
	 *
	 * @param localPort the port number used to bind a socket, a valid port is in the
	 *        range of 1 to 65535, or use 0 to pick an arbitrary unused (ephemeral) port.
	 *        Note that a specified valid port does not ensure a successful bind in
	 *        subsequent discoverer operations due to operating system dependencies.
	 * @param natAware {@code true} to use a NAT (network address translation) aware
	 *        discovery/description mechanism, {@code false} to use the default way
	 */
	public Discoverer(final int localPort, final boolean natAware)
	{
		this(null, localPort, natAware, false);
	}

	/**
	 * Creates a new Discoverer and allows to specify a local host.
	 * <p>
	 * See {@link Discoverer#Discoverer(int, boolean)} for additional description.<br>
	 * The {@code localHost} is used to specify a particular local host address, used
	 * as response destination address when doing discovery / description. By default, subnet matching or the
	 * local host as obtained by {@link InetAddress#getLocalHost()} is used (in that order). The returned
	 * address is quite system dependent and might not always be useful in some
	 * situations. So it can be overruled specifying a local host address using this
	 * constructor.
	 *
	 * @param localHost local host address used for KNXnet/IP description, or
	 *        {@code null} to use the default local host if required
	 * @param localPort the port number used to bind a socket, a valid port is in the
	 *        range of 1 to 65535, or use 0 to pick an arbitrary unused (ephemeral) port.
	 *        Note that a specified valid port does not ensure a successful bind in
	 *        subsequent discoverer operations due to operating system dependencies.
	 * @param natAware {@code true} to use a NAT (network address translation) aware
	 *        discovery/description mechanism, {@code false} to use the default way
	 * @param mcastResponse set {@code true} to use multicasting for search responses
	 *        in KNXnet/IP discovery, {@code false} to use unicast for search
	 *        responses to this local host and port address
	 */
	public Discoverer(final InetAddress localHost, final int localPort, final boolean natAware,
		final boolean mcastResponse)
	{
		if (localPort < 0 || localPort > 0xFFFF)
			throw new KNXIllegalArgumentException("port out of range [0..0xFFFF]");
		host = localHost;
		port = localPort;
		nat = natAware;
		mcast = mcastResponse;

		if (host != null && host.getAddress().length != 4 && !nat)
			throw new KNXIllegalArgumentException("IPv4 address required if NAT is not used (supplied " + host.getHostAddress() + ")");
	}

	Discoverer() {
		host = null;
		port = 0;
		nat = false;
		mcast = false;
	}

	/**
	 * Sets the timeout used for subsequent KNXnet/IP discovery searches; the default timeout is 10 seconds.
	 *
	 * @param timeout timeout &gt; 0
	 * @return this discoverer
	 */
	public Discoverer timeout(final Duration timeout) {
		if (timeout.isNegative() || timeout.isZero())
			throw new KNXIllegalArgumentException("timeout <= 0");
		this.timeout = timeout;
		return this;
	}

	private CompletableFuture<List<Result<SearchResponse>>> search(final Duration timeout) {
		return searchAsync(timeout);
	}

	public CompletableFuture<List<Result<SearchResponse>>> search(final Srp... searchParameters) {
		return searchAsync(timeout(), searchParameters);
	}

	// extended unicast search to server control endpoint
	public CompletableFuture<Result<SearchResponse>> search(final InetSocketAddress serverControlEndpoint,
			final Srp... searchParameters) throws KNXException {

		final InetAddress addr = nat ? host : host != null ? host
				: Net.onSameSubnet(serverControlEndpoint.getAddress()).orElseGet(Discoverer::localHost);
		try {
			final var dc = newChannel(new InetSocketAddress(addr, port));
			// create a new socket address with host, since the socket might
			// return the wildcard address for loopback or default host address; but port
			// is necessarily queried from socket since it might have been 0 before (for ephemeral port)
			final InetSocketAddress local = (InetSocketAddress) dc.getLocalAddress();
			logger.log(DEBUG, "search {0} -> server control endpoint {1}", hostPort(local), hostPort(serverControlEndpoint));

			final boolean tcp = false;
			final InetSocketAddress res = tcp || nat ? new InetSocketAddress(0) : local;

			final byte[] request = PacketHelper.toPacket(new SearchRequest(res, searchParameters));
			dc.send(ByteBuffer.wrap(request), serverControlEndpoint);
			return receiveAsync(dc, serverControlEndpoint, timeout());
		}
		catch (final IOException e) {
			throw new KNXException("search request to " + hostPort(serverControlEndpoint) + " failed on " + addr, e);
		}
	}

	private static InetAddress localHost() {
		try {
			return InetAddress.getLocalHost();
		}
		catch (final UnknownHostException e) {
			throw new KnxRuntimeException("local IP required, but getting local host failed");
		}
	}

	Duration timeout() { return timeout; }

	/**
	 * Starts a new search for KNXnet/IP discovery, the network interface can be
	 * specified.
	 * <p>
	 * The search will continue for {@code timeout} seconds, or infinite if timeout
	 * value is zero. During this time, search responses will get collected asynchronous
	 * in the background by this {@link Discoverer}.<br>
	 * With {@code wait} you can force this method into blocking mode to wait until
	 * the search finished, otherwise the method returns with the search running in the
	 * background.<br>
	 * A search is finished if either the {@code timeout} was reached or the
	 * background receiver stopped.<br>
	 *
	 * @param ni the {@link NetworkInterface} used for sending outgoing multicast
	 *        messages, or {@code null} to use the default multicast interface
	 * @param timeout time window in seconds during which search response messages will
	 *        get collected, timeout &ge; 0. If timeout is zero, no timeout is set, the
	 *        search has to be stopped with {@link #stopSearch()}.
	 * @param wait {@code true} to block until end of search before return
	 * @throws KNXException on network I/O error
	 * @throws InterruptedException if search was interrupted in blocking mode before the
	 *         specified timeout was reached; the search is stopped before passing this
	 *         exception back to the caller
	 * @see NetworkInterface
	 */
	public void startSearch(final NetworkInterface ni, final int timeout, final boolean wait)
		throws KNXException, InterruptedException
	{
		startSearch(port, ni, timeout, wait);
	}

	/**
	 * Starts a new search for KNXnet/IP discovery, the {@code localPort} and network
	 * interface can be specified.
	 * <p>
	 * See documentation for method {@link #startSearch(NetworkInterface, int, boolean)}.<br>
	 * To distinguish between search responses if a user started two or more searches
	 * running concurrently, this method allows to specify a dedicated
	 * {@code localPort}, not using the port set with
	 * {@link #Discoverer(int, boolean)}.
	 *
	 * @param localPort the port used to bind the socket, a valid port is 0 to 65535, if
	 *        {@code localPort} is zero an arbitrary unused (ephemeral) port is
	 *        picked
	 * @param ni the {@link NetworkInterface} used for sending outgoing multicast
	 *        messages, or {@code null} to use the default multicast interface
	 * @param timeout time window in seconds during which search response messages will
	 *        get collected, {@code timeout ≥ 0}. If timeout is zero, no timeout is
	 *        set, the search has to be stopped with {@link #stopSearch()}.
	 * @param wait {@code true} to block until end of search before return
	 * @throws KNXException on network I/O error
	 * @throws InterruptedException if search was interrupted in blocking mode before the
	 *         specified timeout was reached; the search is stopped before passing this
	 *         exception back to the caller
	 * @see NetworkInterface
	 */
	public void startSearch(final int localPort, final NetworkInterface ni, final int timeout,
		final boolean wait) throws KNXException, InterruptedException
	{
		if (timeout < 0)
			throw new KNXIllegalArgumentException("timeout has to be >= 0");
		if (localPort < 0 || localPort > 65535)
			throw new KNXIllegalArgumentException("port out of range [0..0xFFFF]");

		// possibly empty list of netif IP addresses
		final List<InetAddress> l = Optional.ofNullable(ni).map(NetworkInterface::getInetAddresses)
				.map(Collections::list).orElse(new ArrayList<>());
		// use any assigned (IPv4) address of netif, otherwise, use host
		final InetAddress addr = l.stream().filter(ia -> nat || ia instanceof Inet4Address).findFirst().orElse(host(null));

		final CompletableFuture<Void> cf = search(addr, localPort, ni, Duration.ofSeconds(timeout), responses::add);
		if (wait) {
			try {
				cf.get();
			}
			catch (CancellationException | ExecutionException e) {
				logger.log(ERROR, "search completed with error", e);
			}
		}
	}

	/**
	 * Starts a new search for KNXnet/IP discovery on all found network interfaces.
	 * <p>
	 * The search will continue for {@code timeout} seconds, or infinite if timeout
	 * value is zero. During this time, search responses will get collected asynchronous
	 * in the background by this Discoverer.<br>
	 * With {@code wait} you can force this method into blocking mode to wait until
	 * the search finished, otherwise the method returns with the search running in the
	 * background.<br>
	 * A search has finished if either the {@code timeout} was reached, all
	 * background receivers stopped (all responses received) or {@link #stopSearch()} was
	 * invoked.
	 *
	 * @param timeout time window in seconds during which search response messages will
	 *        get collected, timeout &ge; 0. If timeout is 0, no timeout is set, the search
	 *        has to be stopped with {@code stopSearch}.
	 * @param wait {@code true} to block until end of search before return
	 * @throws InterruptedException if search was interrupted in blocking mode before the
	 *         specified timeout was reached; the search is stopped before passing this
	 *         exception back to the caller
	 */
	public void startSearch(final int timeout, final boolean wait) throws InterruptedException
	{
		final CompletableFuture<List<Result<SearchResponse>>> search = search(Duration.ofSeconds(timeout));
		if (!wait)
			return;
		try {
			search.get();
		}
		catch (CancellationException | ExecutionException e) {
			logger.log(ERROR, "search completed with error", e);
		}
		finally {
			stopSearch();
		}
	}

	private CompletableFuture<List<Result<SearchResponse>>> searchAsync(final Duration timeout,
			final Srp... searchParameters) {
		if (timeout.isNegative())
			throw new KNXIllegalArgumentException("timeout has to be >= 0");
		final NetworkInterface[] nifs;
		try {
			nifs = NetworkInterface.networkInterfaces().toArray(NetworkInterface[]::new);
		}
		catch (final SocketException e) {
			return CompletableFuture.failedFuture(e);
		}
		// loopback flag, so we start at most one local search
		boolean lo = false;
		final List<CompletableFuture<Void>> cfs = new ArrayList<>();
		final var responses = Collections.<Result<SearchResponse>>newSetFromMap(new ConcurrentHashMap<>());
		for (final NetworkInterface ni : nifs) {
			// find one IP address we can use for our search on this interface
			for (final Enumeration<InetAddress> ea = ni.getInetAddresses(); ea.hasMoreElements();) {
				final InetAddress a = ea.nextElement();
				// without NAT, we only try IPv4 addresses
				if (!nat && a.getAddress().length != 4)
					logger.log(DEBUG, "skip {0}, not an IPv4 address", a);
				else
					try {
						if (!(lo && a.isLoopbackAddress())) {
							cfs.add(search(a, port, ni, timeout, responses::add, searchParameters));
						}
						if (a.isLoopbackAddress()) {
							lo = true;
						}
					}
					catch (KNXException | RuntimeException e) {
						// we continue on exception, but print a warning for user information
						String causeMsg = "";
						for (Throwable t = e.getCause(); t != null && t != t.getCause(); t = t.getCause()) {
							final String msg = t.getMessage();
							causeMsg = " (" + (msg != null ? msg : t.toString()) + ")";
						}
						logger.log(WARNING, "using {0} at {1}: {2}{3}", a, ni.getName(), e.getMessage(), causeMsg);
					}
			}
		}
		if (cfs.size() == 0)
			return CompletableFuture.failedFuture(
					new KNXException("search could not be started on any network interface"));

		final CompletableFuture<List<Result<SearchResponse>>> search = CompletableFuture
				.allOf(cfs.toArray(new CompletableFuture<?>[0])).thenApply(__ -> List.copyOf(responses));
		search.exceptionally(t -> {
			cfs.forEach(cf -> cf.cancel(false));
			return null;
		});
		return search;
	}

	/**
	 * Stops every search currently performed by this discoverer.
	 * <p>
	 * Already collected search responses from a search will not be removed.
	 */
	public final void stopSearch()
	{
		final ReceiverLoop[] loopers = receivers
				.toArray(new ReceiverLoop[receivers.size()]);
		for (int i = 0; i < loopers.length; i++) {
			final ReceiverLoop loop = loopers[i];
			loop.quit();
		}
		receivers.removeAll(Arrays.asList(loopers));
	}

	/**
	 * Returns {@code true} if a search is currently running.
	 *
	 * @return a {@code boolean} showing the search state
	 */
	public final boolean isSearching()
	{
		return receivers.size() != 0;
	}

	/**
	 * Returns all collected search responses received by searches so far.
	 * <p>
	 * As long as searches are running, new responses might be added to the list of
	 * responses.
	 *
	 * @return list of results with {@link SearchResponse}s
	 * @see #stopSearch()
	 */
	public final List<Result<SearchResponse>> getSearchResponses()
	{
		return Collections.unmodifiableList(responses);
	}

	/**
	 * Removes all search responses collected so far.
	 */
	public final void clearSearchResponses()
	{
		responses.clear();
	}

	/**
	 * Sends a description request to {@code server} and waits at most
	 * {@code timeout} seconds for the answer message to arrive.
	 *
	 * @param server the socket address of the server the description is requested from
	 * @param timeout time window in seconds to wait for answer message, 0 &lt; timeout
	 *        &lt; ({@link Integer#MAX_VALUE} / 1000)
	 * @return the result containing the description response message
	 * @throws KNXException on network I/O error
	 * @throws KNXTimeoutException if the timeout was reached before the description
	 *         response arrived
	 * @throws KNXInvalidResponseException if a received message from {@code server}
	 *         does not match the expected response
	 */
	public Result<DescriptionResponse> getDescription(final InetSocketAddress server, final int timeout)
			throws KNXException {
		if (timeout <= 0 || timeout >= Integer.MAX_VALUE / 1000)
			throw new KNXIllegalArgumentException("timeout out of range");

		final var localhost = host(server.getAddress());
		final var bind = new InetSocketAddress(nat ? null : Net.onSameSubnet(server.getAddress()).orElse(localhost),
				port);
		try (var dc = newChannel(bind)) {
			final var local = (InetSocketAddress) dc.getLocalAddress();
			final byte[] buf = PacketHelper.toPacket(new DescriptionRequest(nat ? null : local));
			dc.send(ByteBuffer.wrap(buf), server);
			final ReceiverLoop looper = new ReceiverLoop(dc, 512, Duration.ofSeconds(timeout), server);
			looper.loop();
			if (looper.thrown != null)
				throw looper.thrown;
			if (looper.res != null)
				return new Result<>(looper.res, NetworkInterface.getByInetAddress(local.getAddress()), local, server);
		}
		catch (final IOException e) {
			throw new KNXException("network failure on getting description from " + hostPort(server), e);
		}
		throw new KNXTimeoutException("timeout, no description response received from " + hostPort(server));
	}

	/**
	 * Starts a search sending a search request message.
	 *
	 * @param localAddr local address to send search request from
	 * @param localPort local port to send search request from
	 * @param ni {@link NetworkInterface} used to send outgoing multicast, or
	 *        {@code null} to use the default multicast interface
	 * @param timeout search timeout, timeout &ge; 0, 0 for an infinite time window
	 * @param notifyResponse consumer for responses
	 * @param searchParameters optional search parameters for extended search
	 * @return the receiver thread for the search started
	 * @throws KNXException
	 */
	private CompletableFuture<Void> search(final InetAddress localAddr, final int localPort, final NetworkInterface ni,
			final Duration timeout, final Consumer< Result<SearchResponse>> notifyResponse,
			final Srp... searchParameters) throws KNXException {
		final var bind = mcast ? new InetSocketAddress(SEARCH_PORT) : new InetSocketAddress(localAddr, localPort);
		try {
			final var channel = newChannel(bind);
			if (ni != null)
				channel.setOption(StandardSocketOptions.IP_MULTICAST_IF, ni);
			if (mcast)
				channel.join(SYSTEM_SETUP_MULTICAST, ni);

			// create a new socket address with the address from a, since the socket might
			// return the wildcard address for loopback or default host address; but port
			// is necessarily queried from socket since in a it might be 0 (for ephemeral port)
			final String nifName = ni != null ? ni.getName() + " " : "";
			final int realLocalPort = ((InetSocketAddress) channel.getLocalAddress()).getPort();
			final var localEndpoint = new InetSocketAddress(localAddr, realLocalPort);
			logger.log(DEBUG, "search on " + nifName + localEndpoint);

			// IP multicast responses MUST be forwarded by NAT without
			// modifications to IP/port, hence, we can safely state them in our HPAI
			final InetSocketAddress res = mcast ? new InetSocketAddress(SYSTEM_SETUP_MULTICAST, realLocalPort)
					: nat ? new InetSocketAddress(0) : localEndpoint;

			final var dst = new InetSocketAddress(SYSTEM_SETUP_MULTICAST, SEARCH_PORT);

			// send extended search request with search params or additional DIBs
			final SearchRequest req;
			if (searchParameters.length > 0)
				req = new SearchRequest(res, searchParameters);
			else
				req = new SearchRequest(res, withDeviceDescription(DIB.DEVICE_INFO, DIB.SUPP_SVC_FAMILIES,
						DIB.AdditionalDeviceInfo, DIB.SecureServiceFamilies, DIB.TunnelingInfo));
			channel.send(ByteBuffer.wrap(PacketHelper.toPacket(req)), dst);

			// only send standard search request if there are no extended search params
			if (searchParameters.length == 0) {
				final byte[] std = PacketHelper.toPacket(new SearchRequest(res));
				channel.send(ByteBuffer.wrap(std), dst);
			}

			return receiveAsync(channel, localEndpoint, timeout, nifName + localAddr.getHostAddress(), notifyResponse);
		}
		catch (IOException | RuntimeException e) {
			throw new KNXException("search request to " + SYSTEM_SETUP_MULTICAST.getHostAddress() + " failed on "
					+ localAddr + ":" + localPort, e);
		}
	}

	private static DatagramChannel newChannel(final InetSocketAddress bind) throws IOException {
		return (DatagramChannel) DatagramChannel.open(StandardProtocolFamily.INET)
				.setOption(StandardSocketOptions.SO_REUSEADDR, true)
				.bind(bind)
				.setOption(StandardSocketOptions.IP_MULTICAST_TTL, 64)
				.configureBlocking(false);
	}

	private synchronized InetAddress host(final InetAddress remote) throws KNXException
	{
		try {
			if (remote == null)
				return InetAddress.getLocalHost();
			if (host == null)
				host = InetAddress.getLocalHost();
			return host;
		}
		catch (final UnknownHostException e) {
			throw new KNXException("on resolving address of local host", e);
		}
	}

	private static final ExecutorService executor = Executor.executor();

	private CompletableFuture<Void> receiveAsync(final DatagramChannel dc, final InetSocketAddress localEndpoint,
		final Duration timeout, final String name, final Consumer< Result<SearchResponse>> notifyResponse) throws IOException
	{
		final ReceiverLoop looper = new ReceiverLoop(dc, localEndpoint, 512, timeout, name
				+ ":" + ((InetSocketAddress) dc.getLocalAddress()).getPort(), notifyResponse);
		final CompletableFuture<Void> cf = CompletableFuture.runAsync(looper, executor);
		cf.exceptionally(t -> {
			looper.quit();
			return null;
		});
		return cf;
	}

	private CompletableFuture<Result<SearchResponse>> receiveAsync(final DatagramChannel dc,
			final InetSocketAddress serverCtrlEndpoint, final Duration timeout) throws IOException {

		final ReceiverLoop looper = new ReceiverLoop(dc, 512, timeout.plusSeconds(1), serverCtrlEndpoint);
		final InetSocketAddress local = (InetSocketAddress) dc.getLocalAddress();
		final NetworkInterface netif;
		if (local.getAddress().isAnyLocalAddress())
			netif = Net.defaultNetif;
		else
			netif = NetworkInterface.getByInetAddress(local.getAddress());

		final var cf = CompletableFuture.runAsync(looper, executor)
				.thenApply(__ -> new Result<>(looper.sr, netif, local, serverCtrlEndpoint))
				.orTimeout(timeout.toMillis(), TimeUnit.MILLISECONDS);
		cf.exceptionally(t -> {
			looper.quit();
			return null;
		});
		return cf;
	}

	private final class ReceiverLoop extends UdpSocketLooper implements Runnable
	{
		private final boolean multicast;
		private final InetSocketAddress server;
		private final NetworkInterface nif;

		// we want this address to return it in a search result even if the socket was not bound
		private final InetSocketAddress localEndpoint;

		// used for description looper
		private DescriptionResponse res;
		private SearchResponse sr;
		private KNXInvalidResponseException thrown;
		private final String id;

		private final Selector selector;
		private final Duration timeout;

		private final Consumer<Result<SearchResponse>> notifyResponse;

		// use for search looper
		// timeout in milliseconds
		ReceiverLoop(final DatagramChannel dc, final InetSocketAddress localEndpoint, final int receiveBufferSize,
				final Duration timeout, final String name, final Consumer< Result<SearchResponse>> notifyResponse)
						throws IOException {
			super(null, false, receiveBufferSize, 0, (int) timeout.toMillis());

			nif = dc.getOption(StandardSocketOptions.IP_MULTICAST_IF);
			this.localEndpoint = localEndpoint;
			multicast = true;
			server = null;
			id = name;

			selector = Selector.open();
			dc.register(selector, SelectionKey.OP_READ);

			this.timeout = timeout;
			this.notifyResponse = notifyResponse;

			receivers.add(this);
		}

		// unicast search to specific server endpoint, and descrption request
		ReceiverLoop(final DatagramChannel dc, final int receiveBufferSize, final Duration timeout,
				final InetSocketAddress queriedServer) throws IOException {
			super(null, true, receiveBufferSize, 0, (int) timeout.toMillis());
			nif = null;
			localEndpoint = null;
			multicast = false;
			server = queriedServer;
			id = "" + dc.getLocalAddress();

			selector = Selector.open();
			dc.register(selector, SelectionKey.OP_READ);

			this.timeout = timeout;

			notifyResponse = null;
		}

		@Override
		public void run()
		{
			Thread.currentThread().setName("Discoverer " + id);
			try {
				loop();
			}
			catch (final IOException e) {
				logger.log(ERROR, "while waiting for response", e);
			}
			finally {
				logger.log(TRACE, "stopped on " + id);
				receivers.remove(this);
			}
		}

		@Override
		public void onReceive(final InetSocketAddress source, final byte[] data, final int offset, final int length)
		{
			try {
				final KNXnetIPHeader h = new KNXnetIPHeader(data, offset);
				final int bodyLen = h.getTotalLength() - h.getStructLength();
				final int svc = h.getServiceType();
				if (h.getTotalLength() > length)
					logger.log(WARNING, "ignore received packet from {0}, packet size {1} > buffer size {2}", source,
							h.getTotalLength(), length);
				else if (multicast && (svc == KNXnetIPHeader.SEARCH_RES || svc == KNXnetIPHeader.SearchResponse)) {
					// if our search is still running, add response if not already added
					synchronized (receivers) {
						if (receivers.contains(this)) {
							final var response = SearchResponse.from(h, data, offset + h.getStructLength());
							final Result<SearchResponse> r = new Result<>(response, nif, localEndpoint, source);
							notifyResponse.accept(r);
							if (!responses.contains(r))
								responses.add(r);
						}
					}
				}
				else if (!multicast && svc == KNXnetIPHeader.DESCRIPTION_RES) {
					if (source.equals(server)) {
						try {
							res = new DescriptionResponse(data, offset + h.getStructLength(), bodyLen);
						}
						catch (final KNXFormatException e) {
							thrown = new KNXInvalidResponseException(
									"invalid description response from " + hostPort(source), e);
						}
						finally {
							quit();
						}
					}
				}
				else if (!multicast && svc == KNXnetIPHeader.SearchResponse) {
					if (source.equals(server)) {
						try {
							sr = SearchResponse.from(h, data, offset + h.getStructLength());
						}
						catch (final KNXFormatException e) {
							thrown = new KNXInvalidResponseException("invalid search response from " + hostPort(source),
									e);
						}
						finally {
							quit();
						}
					}
				}
			}
			catch (final KNXFormatException e) {
				logger.log(INFO, "ignore received packet from {0}, {1}", source, e.getMessage());
			}
			catch (final RuntimeException e) {
				logger.log(WARNING, "error parsing received packet from {0}", source, e);
			}
		}

		@Override
		protected void receive(final byte[] buf) throws IOException {
			var remaining = timeout;
			final var end = Instant.now().plus(remaining);
			while (remaining.toMillis() > 0) {
				if (selector.select(remaining.toMillis()) > 0) {
					for (final var i = selector.selectedKeys().iterator(); i.hasNext();) {
						final var key = i.next();
						final var channel = key.channel();
						final ByteBuffer buffer = ByteBuffer.wrap(buf);
						final var source = ((DatagramChannel) channel).receive(buffer);
						buffer.flip();
						onReceive((InetSocketAddress) source, buf, buffer.position(), buffer.remaining());
						i.remove();
					}
					return;
				}
				remaining = Duration.between(Instant.now(), end);
			}
		}
	}
}
