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

package tuwien.auto.calimero.knxnetip;

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Optional;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.log.LogService;

final class Net {
	private Net() {}

	private static final Logger logger = LogService.getLogger("calimero.knxnetip.Net");


	static final NetworkInterface defaultNetif;
	static {
		try (var s = new MulticastSocket()) {
			defaultNetif = s.getNetworkInterface();
		}
		catch (final IOException e) {
			throw new ExceptionInInitializerError();
		}
	}

	// finds a local IPv4 address with its network prefix "matching" the remote address
	static Optional<InetAddress> onSameSubnet(final InetAddress remote) {
		try {
			return NetworkInterface.networkInterfaces().flatMap(ni -> ni.getInterfaceAddresses().stream())
					.filter(ia -> ia.getAddress() instanceof Inet4Address)
					.peek(ia -> logger.log(Level.TRACE, "match local address {0}/{1} to {2}", ia.getAddress().getHostAddress(),
							ia.getNetworkPrefixLength(), remote.getHostAddress()))
					.filter(ia -> matchesPrefix(ia.getAddress(), ia.getNetworkPrefixLength(), remote))
					.map(ia -> ia.getAddress()).findFirst();
		}
		catch (final SocketException ignore) {}
		return Optional.empty();
	}

	static boolean matchesPrefix(final InetAddress local, final int maskLength, final InetAddress remote)
	{
		final byte[] a1 = local.getAddress();
		final byte[] a2 = remote.getAddress();
		final long mask = (0xffffffffL >> maskLength) ^ 0xffffffffL;
		for (int i = 0; i < a1.length; i++) {
			final int byteMask = (int) ((mask >> (24 - 8 * i)) & 0xff);
			if ((a1[i] & byteMask) != (a2[i] & byteMask))
				return false;
		}
		return true;
	}

	static String hostPort(final InetSocketAddress addr) {
		return addr.getAddress().getHostAddress() + ":" + addr.getPort();
	}

	static InetSocketAddress matchRemoteEndpoint(final InetSocketAddress localEp, final InetSocketAddress remoteEp,
			final boolean useNat) throws KNXException {
		if (localEp.isUnresolved())
			throw new KNXIllegalArgumentException("unresolved address " + localEp);
		if (!localEp.getAddress().isAnyLocalAddress())
			return localEp;

		try {
			final InetAddress addr = useNat ? null : Optional.ofNullable(remoteEp.getAddress())
					.flatMap(Net::onSameSubnet).orElse(InetAddress.getLocalHost());
			return new InetSocketAddress(addr, localEp.getPort());
		}
		catch (final UnknownHostException e) {
			throw new KNXException("no local host address available", e);
		}
	}
}
