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

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static tuwien.auto.calimero.knxnetip.KNXnetIPConnection.BlockingMode.WaitForAck;
import static tuwien.auto.calimero.knxnetip.KNXnetIPConnection.BlockingMode.WaitForCon;
import static tuwien.auto.calimero.knxnetip.KNXnetIPTunnel.TunnelingLayer.LinkLayer;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.time.Duration;

import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAckTimeoutException;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.ReturnCode;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.cemi.CemiTData;
import tuwien.auto.calimero.knxnetip.KNXConnectionClosedException;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.knxnetip.KNXnetIPDevMgmt;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.KNXnetIPTunnel;
import tuwien.auto.calimero.knxnetip.LostMessageEvent;
import tuwien.auto.calimero.knxnetip.RateLimitEvent;
import tuwien.auto.calimero.knxnetip.RoutingBusyEvent;
import tuwien.auto.calimero.knxnetip.RoutingListener;
import tuwien.auto.calimero.knxnetip.SecureConnection;
import tuwien.auto.calimero.knxnetip.TcpConnection;
import tuwien.auto.calimero.knxnetip.TcpConnection.SecureSession;
import tuwien.auto.calimero.knxnetip.TunnelingListener;
import tuwien.auto.calimero.knxnetip.servicetype.TunnelingFeature;
import tuwien.auto.calimero.knxnetip.servicetype.TunnelingFeature.InterfaceFeature;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;

/**
 * Implementation of the KNX network link based on the KNXnet/IP protocol, using a {@link KNXnetIPConnection}.
 * <p>
 * Once a link has been closed, it is not available for further link communication, i.e. it can't be reopened.
 * <p>
 * Link-layer tunneling is supported for tunneling protocols v1 and v2.
 * <p>
 * If KNXnet/IP routing is used as base protocol, the send methods with wait for confirmation behave equally like
 * without wait specified, since routing is an unconfirmed protocol. This implies that no confirmation frames are
 * generated, thus {@link NetworkLinkListener#confirmation(FrameEvent)} is not used.
 * <p>
 * IP address considerations:<br>
 * On more IP addresses assigned to the local host (on possibly several local network interfaces), the default chosen
 * local host address can differ from the expected. In this situation, the local endpoint has to be specified manually
 * during instantiation.<br>
 * Network Address Translation (NAT) aware communication can only be used, if the KNXnet/IP server of the remote
 * endpoint supports it. Otherwise, connection timeouts will occur. With NAT enabled, KNXnet/IP accepts IPv6 addresses.
 * By default, the KNXnet/IP protocol only works with IPv4 addresses.
 *
 * @author B. Malinowsky
 */
public class KNXNetworkLinkIP extends AbstractLink<KNXnetIPConnection>
{
	/**
	 * KNXnet/IP system setup multicast address, KNXnet/IP routers are by default members of that multicast group.
	 */
	public static final InetAddress DefaultMulticast;
	static {
		try {
			DefaultMulticast = InetAddress.getByName("224.0.23.12");
		}
		catch (final UnknownHostException e) {
			throw new KnxRuntimeException("KNXnet/IP system setup multicast address", e);
		}
	}

	/**
	 * Service mode for link layer tunneling.
	 */
	protected static final int TUNNELING = 1;

	/**
	 * Service mode for link layer tunneling v2.
	 */
	protected static final int TunnelingV2 = 3;

	/**
	 * Service mode for cEMI T-Data device management.
	 */
	protected static final int DevMgmt = 4;

	/**
	 * Service mode for routing.
	 */
	protected static final int ROUTING = 2;

	private final int mode;

	private KNXnetIPDevMgmt mgmt;

	/**
	 * Creates a new network link using KNXnet/IP tunneling (internally using a {@link KNXnetIPConnection}) to a remote
	 * KNXnet/IP server endpoint.
	 *
	 * @param localEP the local control endpoint of the link to use, supply the wildcard address to use a local IP on
	 *        the same subnet as {@code remoteEP} and an ephemeral port number
	 * @param remoteEP the remote endpoint of the link to communicate with; this is the KNXnet/IP server control
	 *        endpoint
	 * @param useNAT {@code true} to use network address translation (NAT) in tunneling service mode,
	 *        {@code false} to use the default (non aware) mode
	 * @param settings medium settings defining device and KNX medium specifics for communication
	 * @return the network link in open state
	 * @throws KNXException on failure establishing link using the KNXnet/IP connection
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	public static KNXNetworkLinkIP newTunnelingLink(final InetSocketAddress localEP, final InetSocketAddress remoteEP,
		final boolean useNAT, final KNXMediumSettings settings) throws KNXException, InterruptedException
	{
		return new KNXNetworkLinkIP(TUNNELING, localEP, remoteEP, useNAT, settings);
	}

	/**
	 * Creates a new network link using unsecured KNXnet/IP tunneling v2 over TCP to a remote KNXnet/IP server endpoint.
	 *
	 * @param connection a TCP connection to the server (if the connection state is not connected, link setup will
	 *        establish the connection); closing the link will not close the TCP connection
	 * @param settings medium settings defining device and KNX medium specifics for communication
	 * @return the network link in open state
	 * @throws KNXException on failure establishing the link
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	public static KNXNetworkLinkIP newTunnelingLink(final TcpConnection connection, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		return new KNXNetworkLinkIP(TunnelingV2, KNXnetIPTunnel.newTcpTunnel(LinkLayer, connection,
				settings.getDeviceAddress()), settings);
	}

	public static KNXNetworkLinkIP newSecureTunnelingLink(final InetSocketAddress localEP, final InetSocketAddress remoteEP,
		final boolean useNat, final byte[] deviceAuthCode, final int userId, final byte[] userKey, final KNXMediumSettings settings)
		throws KNXException, InterruptedException {
		final KNXnetIPConnection c = SecureConnection.newTunneling(LinkLayer, localEP, remoteEP, useNat, deviceAuthCode, userId, userKey);
		return new KNXNetworkLinkIP(TunnelingV2, c, settings);
	}

	/**
	 * Creates a new network link using KNX IP secure tunneling over TCP to a remote KNXnet/IP server endpoint.
	 *
	 * @param session a secure session for the server (session state is allowed to be not authenticated);
	 *        closing the link will not close the session
	 * @param settings medium settings defining device and KNX medium specifics for communication
	 * @return the network link in open state
	 * @throws KNXException KNXException on failure establishing the link
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	public static KNXNetworkLinkIP newSecureTunnelingLink(final SecureSession session, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		final KNXnetIPConnection c = SecureConnection.newTunneling(LinkLayer, session, settings.getDeviceAddress());
		return new KNXNetworkLinkIP(TunnelingV2, c, settings);
	}

	/**
	 * Creates a new network link using the {@link KNXnetIPRouting} protocol, with the local endpoint specified by a
	 * network interface.
	 *
	 * @param netIf local network interface used to join the multicast group and for sending, use {@code null} for
	 *        the host's default multicast interface
	 * @param mcGroup address of the multicast group to join, use {@link #DefaultMulticast} for the default KNX IP
	 *        multicast address
	 * @param settings medium settings defining device and medium specifics needed for communication
	 * @return the network link in open state
	 * @throws KNXException on failure establishing link using the KNXnet/IP connection
	 */
	public static KNXNetworkLinkIP newRoutingLink(final NetworkInterface netIf, final InetAddress mcGroup,
		final KNXMediumSettings settings) throws KNXException
	{
		try {
			return new KNXNetworkLinkIP(ROUTING, new KNXnetIPRouting(netIf, mcGroup), settings);
		}
		catch (final InterruptedException unreachable) {
			throw new IllegalStateException();
		}
	}

	/**
	 * Creates a new network link using the {@link KNXnetIPRouting} protocol, with the local endpoint specified by an IP
	 * address.
	 *
	 * @param localEP the IP address bound to a local network interface for joining the multicast group
	 * @param mcGroup address of the multicast group to join, use {@link #DefaultMulticast} for the default KNX IP
	 *        multicast address
	 * @param settings medium settings defining device and medium specifics needed for communication
	 * @return the network link in open state
	 * @throws KNXException on failure establishing link using the KNXnet/IP connection
	 */
	public static KNXNetworkLinkIP newRoutingLink(final InetAddress localEP, final InetAddress mcGroup,
		final KNXMediumSettings settings) throws KNXException
	{
		try {
			return newRoutingLink(netif(localEP), mcGroup, settings);
		}
		catch (final SocketException e) {
			throw new KNXException("error getting network interface: " + e.getMessage());
		}
	}

	/**
	 * Creates a new secure network link using the KNX IP Secure Routing protocol.
	 *
	 * @param netif local network interface used to join the multicast group and for sending
	 * @param mcGroup address of the multicast group to join, use {@link #DefaultMulticast} for the default KNX IP
	 *        multicast address
	 * @param groupKey KNX IP Secure group key (backbone key), {@code groupKey.length == 16}
	 * @param latencyTolerance time window for accepting secure multicasts, depending on max. end-to-end network latency
	 *        (typically 500 ms to 5000 ms), {@code 0 < latencyTolerance.toMillis() ≤ 8000}
	 * @param settings medium settings defining device and medium specifics needed for communication
	 * @return the network link in open state
	 * @throws KNXException on failure establishing link using the KNXnet/IP connection
	 * @throws InterruptedException on thread interrupt while establishing link
	 */
	public static KNXNetworkLinkIP newSecureRoutingLink(final NetworkInterface netif, final InetAddress mcGroup,
			final byte[] groupKey, final Duration latencyTolerance, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		return new KNXNetworkLinkIP(ROUTING, SecureConnection.newRouting(netif, mcGroup, groupKey, latencyTolerance),
				settings);
	}

	/**
	 * Creates a new network link over unsecured UDP to a remote KNX IP device for KNXnet/IP cEMI T-Data device management.
	 *
	 * @param localEp the local control endpoint of the link to use, supply the wildcard address to use a local IP on
	 *        the same subnet as {@code remoteEP} and an ephemeral port number
	 * @param remoteEp the remote endpoint of the link to communicate with
	 * @param useNat {@code true} to use network address translation (NAT) in tunneling service mode,
	 *        {@code false} to use the default (non aware) mode
	 * @param settings medium settings defining device and KNX medium specifics for communication
	 * @return the network link in open state
	 * @throws KNXException on failure establishing the link
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	public static KNXNetworkLinkIP newDeviceManagementLink(final InetSocketAddress localEp,
			final InetSocketAddress remoteEp, final boolean useNat, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		return new KNXNetworkLinkIP(DevMgmt, new KNXnetIPDevMgmt(localEp, remoteEp, useNat), settings);
	}

	/**
	 * Creates a new network link over unsecured TCP to a remote KNX IP device for KNXnet/IP cEMI T-Data device management.
	 *
	 * @param connection a TCP connection to the KNX IP device (if the connection state is not connected, link setup will
	 *        establish the connection); closing the link will not close the TCP connection
	 * @param settings medium settings defining device and KNX medium specifics for communication
	 * @return the network link in open state
	 * @throws KNXException on failure establishing the link
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	public static KNXNetworkLinkIP newDeviceManagementLink(final TcpConnection connection,
			final KNXMediumSettings settings) throws KNXException, InterruptedException {
		return new KNXNetworkLinkIP(DevMgmt, new KNXnetIPDevMgmt(connection), settings);
	}

	/**
	 * Creates a new network link using KNX IP secure to a remote KNX IP device for KNXnet/IP cEMI T-Data device management.
	 *
	 * @param session a secure session for the KNX IP device (session state is allowed to be not authenticated);
	 *        closing the link will not close the session
	 * @param settings medium settings defining device and KNX medium specifics for communication
	 * @return the network link in open state
	 * @throws KNXException on failure establishing the link
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	public static KNXNetworkLinkIP newSecureDeviceManagementLink(final SecureSession session,
			final KNXMediumSettings settings) throws KNXException, InterruptedException {
		return new KNXNetworkLinkIP(DevMgmt, SecureConnection.newDeviceManagement(session), settings);
	}


	/**
	 * Creates a new network link based on the KNXnet/IP protocol, using a {@link KNXnetIPConnection}.
	 *
	 * @param serviceMode mode of communication to open, {@code serviceMode} is one of the service mode constants
	 *        (e.g. {@link #TUNNELING}); depending on the mode set, the expected local/remote endpoints might differ
	 * @param localEP the local endpoint of the link to use;<br>
	 *        - in tunneling mode (point-to-point), this is the client control endpoint, use {@code null} for the
	 *        default local host and an ephemeral port number<br>
	 *        - in {@link #ROUTING} mode, specifies the multicast interface, i.e., the local network interface is taken
	 *        that has the IP address bound to it (if IP address is bound more than once, it's undefined which interface
	 *        is returned), the port is not used; use {@code null} for {@code localEP} or an unresolved IP
	 *        address to take the host's default multicast interface
	 * @param remoteEP the remote endpoint of the link to communicate with;<br>
	 *        - in tunneling mode (point-to-point), this is the server control endpoint <br>
	 *        - in {@link #ROUTING} mode, the IP address specifies the multicast group to join, the port is not used;
	 *        use {@code null} for {@code remoteEP} or an unresolved IP address to take the default multicast
	 *        group
	 * @param useNAT {@code true} to use network address translation in tunneling service mode, {@code false}
	 *        to use the default (non aware) mode; parameter is ignored for routing
	 * @param settings medium settings defining device and medium specifics needed for communication
	 * @throws KNXException on failure establishing link using the KNXnet/IP connection
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	protected KNXNetworkLinkIP(final int serviceMode, final InetSocketAddress localEP, final InetSocketAddress remoteEP,
		final boolean useNAT, final KNXMediumSettings settings) throws KNXException, InterruptedException
	{
		this(serviceMode, newConnection(serviceMode, localEP, remoteEP, useNAT), settings);
		if (serviceMode == TUNNELING)
			configureWithServerSettings(localEP, remoteEP, useNAT);
	}

	/**
	 * Creates a new network link with {@code serviceMode} based on the supplied KNXnet/IP connection.
	 *
	 * @param serviceMode mode of communication, one of the service mode constants {@link #TUNNELING},
	 *        {@link #TunnelingV2}, or {@link #ROUTING}
	 * @param c a KNXnet/IP tunneling or routing connection in open state
	 * @param settings medium settings defining device and medium specifics needed for communication
	 * @throws InterruptedException if a feature info service got interrupted
	 * @throws KNXConnectionClosedException if the tunneling connection got closed while executing feature info services
	 * @throws KNXAckTimeoutException if a timeout occurred during feature info services
	 */
	protected KNXNetworkLinkIP(final int serviceMode, final KNXnetIPConnection c, final KNXMediumSettings settings)
		throws KNXAckTimeoutException, KNXConnectionClosedException, InterruptedException {
		super(c, createLinkName(c.getRemoteAddress()), settings);
		cEMI = true;

		mode = serviceMode;
		conn.addConnectionListener(notifier);
		if (c instanceof KNXnetIPTunnel && mode == TunnelingV2) {
			notifier.registerEventType(TunnelingFeature.class);

			final var tunnel = (KNXnetIPTunnel) c;
			tunnel.addConnectionListener(new TunnelingListener() {
				@Override
				public void featureResponse(final TunnelingFeature feature) {
					if (valid(feature)) {
						if (feature.featureId() == InterfaceFeature.MaxApduLength)
							getKNXMedium().setMaxApduLength(unsigned(feature.featureValue().get()));
						if (feature.featureId() == InterfaceFeature.IndividualAddress)
							setTunnelingAddress(feature);
					}
					dispatchCustomEvent(feature);
				}

				@Override
				public void featureInfo(final TunnelingFeature feature) {
					if (!valid(feature))
						return;
					if (feature.featureId() == InterfaceFeature.ConnectionStatus) {
						final var connected = feature.featureValue().get()[0] == 1;
						if (connected)
							logger.log(INFO, "subnet connected");
						else
							logger.log(WARNING, "no connection to subnet");
					}
					if (feature.featureId() == InterfaceFeature.IndividualAddress)
						setTunnelingAddress(feature);
					dispatchCustomEvent(feature);
				}

				private boolean valid(final TunnelingFeature feature) {
					final boolean valid = feature.status() == ReturnCode.Success;
					if (!valid)
						logger.log(WARNING, "received {0}", feature);
					return valid;
				}

				@Override
				public void frameReceived(final FrameEvent e) {}

				private void setTunnelingAddress(final TunnelingFeature feature) {
					getKNXMedium().setDeviceAddress(new IndividualAddress(feature.featureValue().get()));
				}
			});
			try {
				tunnel.send(InterfaceFeature.EnableFeatureInfoService, (byte) 1);
			}
			catch (final KNXAckTimeoutException e) {
				throw e;
			}
			catch (final KNXTimeoutException ok) {}
			getTunnelingFeature(tunnel, InterfaceFeature.IndividualAddress);
			getTunnelingFeature(tunnel, InterfaceFeature.MaxApduLength);
			getTunnelingFeature(tunnel, InterfaceFeature.DeviceDescriptorType0);
		}
		else if (c instanceof KNXnetIPRouting) {
			notifier.registerEventType(LostMessageEvent.class);
			notifier.registerEventType(RoutingBusyEvent.class);
			notifier.registerEventType(RateLimitEvent.class);

			c.addConnectionListener(new RoutingListener() {
				@Override
				public void frameReceived(final FrameEvent e) {}

				@Override
				public void routingBusy(final RoutingBusyEvent e) {
					dispatchCustomEvent(e);
				}

				@Override
				public void lostMessage(final LostMessageEvent e) {
					dispatchCustomEvent(e);
				}

				@Override
				public void rateLimit(final RateLimitEvent e) {
					dispatchCustomEvent(e);
				}
			});
		}
	}

	private void getTunnelingFeature(final KNXnetIPTunnel tunnel, final InterfaceFeature feature)
			throws KNXConnectionClosedException, KNXAckTimeoutException, InterruptedException {
		try {
			tunnel.send(feature);
		}
		catch (final KNXAckTimeoutException e) {
			throw e;
		}
		catch (final KNXTimeoutException e) {
			// no tunneling feature response, which is fine
		}
	}

	/**
	 * {@inheritDoc} When communicating with a KNX network which uses open medium, messages are broadcasted within
	 * domain (as opposite to system broadcast) by default. Specify {@code dst = null} for system broadcast.
	 */
	@Override
	public void sendRequest(final KNXAddress dst, final Priority p, final byte[] nsdu)
			throws KNXLinkClosedException, KNXTimeoutException {
		send(msgCode(), dst, p, nsdu, false);
	}

	/**
	 * {@inheritDoc} When communicating with a KNX network which uses open medium, messages are broadcasted within
	 * domain (as opposite to system broadcast) by default. Specify {@code dst null} for system broadcast.
	 */
	@Override
	public void sendRequestWait(final KNXAddress dst, final Priority p, final byte[] nsdu)
			throws KNXTimeoutException, KNXLinkClosedException {
		send(msgCode(), dst, p, nsdu, true);
	}

	private int msgCode() {
		return mode == KNXNetworkLinkIP.ROUTING ? CEMILData.MC_LDATA_IND
				: mode == KNXNetworkLinkIP.DevMgmt ? CemiTData.IndividualRequest : CEMILData.MC_LDATA_REQ;
	}

	@Override
	public String toString()
	{
		return (mode == ROUTING ? "routing " : "tunneling ") + super.toString();
	}

	@Override
	protected void onSend(final KNXAddress dst, final byte[] msg, final boolean waitForCon)
	{
		throw new IllegalStateException("KNXnet/IP uses cEMI only");
	}

	@Override
	protected void onSend(final CEMILData msg, final boolean waitForCon)
			throws KNXTimeoutException, KNXLinkClosedException {
		doSend(msg, waitForCon);
	}

	@Override
	protected void onSend(final CemiTData msg) throws KNXTimeoutException, KNXLinkClosedException {
		doSend(msg, false);
	}

	private void doSend(final CEMI msg, final boolean waitForCon)
			throws KNXTimeoutException, KNXLinkClosedException {
		try {
			logger.log(DEBUG, "send {0}{1}", (waitForCon ? "(wait for confirmation) " : ""), msg);
			conn.send(msg, waitForCon ? WaitForCon : WaitForAck);

			if (msg instanceof CEMILData)
				logger.log(TRACE, "send {0}->{1} succeeded", ((CEMILData) msg).getSource(),
						((CEMILData) msg).getDestination());
			else
				logger.log(TRACE, "send {0}->{1}:{2} succeeded", "local", conn.getRemoteAddress().getAddress(),
						conn.getRemoteAddress().getPort());
		}
		catch (final InterruptedException e) {
			close();
			Thread.currentThread().interrupt();
			throw new KNXLinkClosedException("link closed (interrupted)");
		}
		catch (final KNXConnectionClosedException e) {
			close();
			throw new KNXLinkClosedException("link closed, " + e.getMessage());
		}
	}

	@Override
	@SuppressWarnings("try")
	void baosMode(final boolean enable) throws KNXException, InterruptedException {
		try (var __ = newMgmt(mgmtLocalEp, mgmtRemoteEp, mgmtNat)) {
			super.baosMode(enable);
		}
	}

	@Override
	void onSend(final CEMIDevMgmt frame)
			throws KNXTimeoutException, KNXConnectionClosedException, InterruptedException {
		mgmt.send(frame, WaitForCon);
	}

	// need to store mgmt config for baos mode switch
	private InetSocketAddress mgmtLocalEp;
	private InetSocketAddress mgmtRemoteEp;
	private boolean mgmtNat;

	@SuppressWarnings("try")
	private void configureWithServerSettings(final InetSocketAddress localEP, final InetSocketAddress serverCtrlEP,
			final boolean useNat) throws InterruptedException {
		mgmtLocalEp = localEP;
		mgmtRemoteEp = serverCtrlEP;
		mgmtNat = useNat;
		try (var __ = newMgmt(localEP, serverCtrlEP, useNat)) {
			mediumType();
			setMaxApduLength();
		}
		catch (KNXException | RuntimeException e) {
			logger.log(WARNING, "skip link configuration (use defaults)", e);
		}
	}

	private KNXnetIPDevMgmt newMgmt(final InetSocketAddress localEP, final InetSocketAddress serverCtrlEP,
			final boolean useNat) throws KNXException, InterruptedException {
		mgmt = new KNXnetIPDevMgmt(new InetSocketAddress(localEP.getAddress(), 0), serverCtrlEP, useNat);
		mgmt.addConnectionListener(e -> onDevMgmt((CEMIDevMgmt) e.getFrame()));
		return mgmt;
	}

	private static KNXnetIPConnection newConnection(final int serviceMode, final InetSocketAddress localEP,
		final InetSocketAddress remoteEP, final boolean useNAT) throws KNXException, InterruptedException
	{
		switch (serviceMode) {
		case TUNNELING:
		case TunnelingV2:
			final InetSocketAddress local = localEP == null ? new InetSocketAddress(0) : localEP;
			return new KNXnetIPTunnel(LinkLayer, local, remoteEP, useNAT);
		case ROUTING:
			NetworkInterface netIf = null;
			if (localEP != null && !localEP.isUnresolved())
				try {
					netIf = NetworkInterface.getByInetAddress(localEP.getAddress());
				}
				catch (final SocketException e) {
					throw new KNXException("error getting network interface: " + e.getMessage());
				}
			final InetAddress mcast = remoteEP != null ? remoteEP.getAddress() : null;
			return new KNXnetIPRouting(netIf, mcast);
		default:
			throw new KNXIllegalArgumentException("unknown service mode " + serviceMode);
		}
	}

	private static String createLinkName(final InetSocketAddress endpt)
	{
		if (endpt == null)
			return KNXnetIPRouting.DEFAULT_MULTICAST;
		// do our own IP:port string, since InetAddress.toString() always prepends a '/'
		final String host = (endpt.isUnresolved() ? endpt.getHostString() : endpt.getAddress().getHostAddress());
		final int p = endpt.getPort();
		if (p > 0)
			return host + ":" + p;
		return host;
	}

	private static NetworkInterface netif(final InetAddress addr) throws SocketException, KNXException {
		final var netif = NetworkInterface.getByInetAddress(addr);
		if (netif == null && !addr.isAnyLocalAddress())
			throw new KNXException("no network interface with the specified IP address " + addr.getHostAddress());
		return netif;
	}
}
