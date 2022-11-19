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

import static java.lang.System.Logger.Level.INFO;
import static tuwien.auto.calimero.knxnetip.KNXnetIPTunnel.TunnelingLayer.BusMonitorLayer;

import java.net.InetSocketAddress;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.knxnetip.KNXnetIPConnection;
import tuwien.auto.calimero.knxnetip.KNXnetIPTunnel;
import tuwien.auto.calimero.knxnetip.SecureConnection;
import tuwien.auto.calimero.knxnetip.TcpConnection;
import tuwien.auto.calimero.knxnetip.TcpConnection.SecureSession;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;

/**
 * Implementation of the KNX network monitor link based on the KNXnet/IP protocol, using a
 * {@link KNXnetIPConnection}. Once a monitor has been closed, it is not available for further link
 * communication, i.e., it can't be reopened.
 * <p>
 * Tunneling on bus monitor layer is supported for tunneling protocols v1 and v2.
 * <p>
 * Pay attention to the IP address consideration stated in the API documentation of class
 * {@link KNXNetworkLinkIP}.
 *
 * @author B. Malinowsky
 */
public class KNXNetworkMonitorIP extends AbstractMonitor<KNXnetIPConnection>
{
	/**
	 * Creates a new monitor link using unsecured KNXnet/IP tunneling v2 over TCP to a remote KNXnet/IP server endpoint.
	 *
	 * @param connection a TCP connection to the server (if the connection state is not connected, link setup will
	 *        establish the connection); closing the link will not close the TCP connection
	 * @param settings medium settings defining device and KNX medium specifics for communication
	 * @return the monitor link in open state
	 * @throws KNXException on failure establishing the link
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	public static KNXNetworkMonitorIP newMonitorLink(final TcpConnection connection, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		return new KNXNetworkMonitorIP(KNXnetIPTunnel.newTcpTunnel(BusMonitorLayer, connection,
				settings.getDeviceAddress()), settings);
	}

	/**
	 * Creates a new monitor link using KNX IP secure tunneling over TCP to a remote KNXnet/IP server endpoint.
	 *
	 * @param session a secure session for the server (session state is allowed to be not authenticated);
	 *        closing the link will not close the session
	 * @param settings medium settings defining device and KNX medium specifics for communication
	 * @return the monitor link in open state
	 * @throws KNXException on failure establishing the link
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	public static KNXNetworkMonitorIP newSecureMonitorLink(final SecureSession session, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		final KNXnetIPConnection c = SecureConnection.newTunneling(BusMonitorLayer, session, settings.getDeviceAddress());
		return new KNXNetworkMonitorIP(c, settings);
	}

	/**
	 * Not part of the KNX specification.
	 */
	public static KNXNetworkMonitorIP newSecureMonitorLink(final InetSocketAddress localEP, final InetSocketAddress remoteEP,
		final boolean useNat, final byte[] deviceAuthCode, final int userId, final byte[] userKey, final KNXMediumSettings settings)
		throws KNXException, InterruptedException {
		final KNXnetIPConnection c = SecureConnection.newTunneling(BusMonitorLayer, localEP, remoteEP, useNat, deviceAuthCode, userId,
				userKey);
		return new KNXNetworkMonitorIP(c, settings);
	}

	/**
	 * Creates a new network monitor based on the KNXnet/IP protocol for accessing the KNX network.
	 *
	 * @param localEP the local control endpoint to use for the link, supply the wildcard address to use a local IP on
	 *        the same subnet as {@code remoteEP} and an ephemeral port number
	 * @param remoteEP the remote endpoint of the link; this is the server control endpoint
	 * @param useNAT {@code true} to use network address translation in the KNXnet/IP protocol, {@code false}
	 *        to use the default (non aware) mode
	 * @param settings medium settings defining the specific KNX medium needed for decoding raw frames received from the
	 *        KNX network
	 * @throws KNXException on failure establishing the link
	 * @throws InterruptedException on interrupted thread while establishing link
	 */
	public KNXNetworkMonitorIP(final InetSocketAddress localEP, final InetSocketAddress remoteEP,
		final boolean useNAT, final KNXMediumSettings settings)
			throws KNXException, InterruptedException
	{
		this(new KNXnetIPTunnel(BusMonitorLayer, localEndpoint(localEP), remoteEP, useNAT), settings);
	}

	/**
	 * Creates a new network monitor using the supplied the KNXnet/IP protocol for accessing the KNX
	 * network.
	 *
	 * @param conn an open KNXnet/IP connection in busmonitor layer, the link takes ownership
	 * @param settings medium settings defining the specific KNX medium needed for decoding raw
	 *        frames received from the KNX network
	 */
	protected KNXNetworkMonitorIP(final KNXnetIPConnection conn, final KNXMediumSettings settings)
	{
		super(conn, monitorName(conn.getRemoteAddress()), settings);
		logger.log(INFO, "in busmonitor mode - ready to receive");
		conn.addConnectionListener(notifier);
	}

	private static InetSocketAddress localEndpoint(final InetSocketAddress local)
	{
		if (local != null)
			return local;
		return new InetSocketAddress(0);
	}

	private static String monitorName(final InetSocketAddress remote)
	{
		// do our own IP:port string, since InetAddress.toString() always prepends a '/'
		final String host = (remote.isUnresolved() ? remote.getHostString() : remote.getAddress().getHostAddress());
		return "monitor " + host + ":" + remote.getPort();
	}
}
