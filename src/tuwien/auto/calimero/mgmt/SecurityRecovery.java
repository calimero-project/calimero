/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2022, 2022 B. Malinowsky

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

package tuwien.auto.calimero.mgmt;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.TRACE;

import java.lang.System.Logger;
import java.lang.invoke.MethodHandles;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXRemoteException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.secure.Keyring;
import tuwien.auto.calimero.secure.Keyring.Interface;
import tuwien.auto.calimero.secure.KnxSecureException;
import tuwien.auto.calimero.secure.Security;


/**
 * Recovery requires the device tool keys in {@link Security} for accessing KNX devices.
 */
public final class SecurityRecovery {
	private static final Logger logger = LogService.getLogger(MethodHandles.lookup().lookupClass());

	private final KNXNetworkLink link;
	private final Security security;


	/**
	 * Creates a new instance for security recovery, using {@link Security#defaultInstallation} for secure management.
	 *
	 * @param link network link used for communication with a KNX network, SecurityRecovery does not take ownership
	 */
	public SecurityRecovery(final KNXNetworkLink link) {
		this.link = link;
		this.security = Security.defaultInstallation();
	}

	/**
	 * Creates a new instance for security recovery, using {@code security} for secure management.
	 *
	 * @param link network link used for communication with a KNX network, SecurityRecovery does not take ownership
	 */
	public SecurityRecovery(final KNXNetworkLink link, final Security security) {
		this.link = link;
		this.security = security;
	}

	/**
	 * Returns the last valid sequence number of the current network link address using the linked devices configured in
	 * the corresponding keyring interface.
	 *
	 * @param interfaces list of keyring interfaces to use for querying the linked devices
	 * @return last valid sending sequence number for the network link address
	 * @throws KnxSecureException if no last valid sequence number could be determined from any of the linked devices
	 * @throws KNXLinkClosedException if link got closed
	 * @throws InterruptedException on interrupted thread
	 */
	public long lastValidSequenceNumber(final List<Keyring.Interface> interfaces)
			throws KNXLinkClosedException, InterruptedException {
		final var ourAddress = link.getKNXMedium().getDeviceAddress();
		final var ourInterface = interfaces.stream().filter(intf -> intf.address().equals(ourAddress)).findFirst()
				.orElseThrow(() -> new KnxSecureException(
						ourAddress + " is not configured as secure interface in the keyring"));
		final var interfaceAddresses = interfaces.stream().map(Interface::address).collect(Collectors.toList());

		final var linkedDevices = ourInterface.groups().values().stream().flatMap(Set::stream).distinct()
				.filter(Predicate.not(interfaceAddresses::contains)).collect(Collectors.toList());

		return lastValidSequenceNumber(linkedDevices);
	}

	/**
	 * Returns the last valid sequence number of the current network link address using the given linked devices.
	 *
	 * @param linkedDevices linked devices to query
	 * @return last valid sending sequence number for the network link address
	 * @throws KnxSecureException if no last valid sequence number could be determined from any of the linked devices
	 * @throws KNXLinkClosedException if link got closed
	 * @throws InterruptedException on interrupted thread
	 */
	public long lastValidSequenceNumber(final Iterable<IndividualAddress> linkedDevices)
			throws KNXLinkClosedException, InterruptedException {
		return lastValidSequenceNumber(link.getKNXMedium().getDeviceAddress(), linkedDevices);
	}

	/**
	 * Returns the last valid sequence number of {@code address} using the given linked devices.
	 *
	 * @param address address for which to determine the last valid sequence number
	 * @param linkedDevices linked devices to query
	 * @return last valid sending sequence number for {@code address}
	 * @throws KnxSecureException if no last valid sequence number could be determined from any of the linked devices
	 * @throws KNXLinkClosedException if link got closed
	 * @throws InterruptedException on interrupted thread
	 */
	public long lastValidSequenceNumber(final IndividualAddress address,
			final Iterable<IndividualAddress> linkedDevices) throws KNXLinkClosedException, InterruptedException {

		try (var mc = new ManagementClientImpl(link, security)) {
			for (final var device : linkedDevices) {
				try (var dst = mc.createDestination(device, false)) {
					final long seq = readLastValidSeq(mc, dst, address);
					if (seq >= 0)
						return seq;
				}
				catch (KNXTimeoutException | KNXRemoteException | KNXDisconnectException | KnxSecureException e) {
					logger.log(DEBUG, "no last valid sequence number found for {0} in device {1}: {2}", address, device, e.getMessage());
					// we continue with the next linked device
				}
			}
			throw new KnxSecureException("no last valid sequence number entry found for " + address);
		}
	}

	public Map<IndividualAddress, Long> lastValidSequenceNumbers(final Iterable<IndividualAddress> senders)
			throws KNXLinkClosedException, InterruptedException {
		final var lastValidSeqs = new HashMap<IndividualAddress, Long>();
		try (var mc = new ManagementClientImpl(link, security)) {
			for (final var device : senders) {
				try (var dst = mc.createDestination(device, false)) {
					final long seq = readSeqSending(mc, dst);
					if (seq > 0)
						lastValidSeqs.put(device, seq - 1);
				}
				catch (KNXTimeoutException | KNXRemoteException | KNXDisconnectException | KnxSecureException e) {
					logger.log(DEBUG, "failed reading sequence number of {0}: {1}", device, e.getMessage());
				}
			}
		}
		return lastValidSeqs;
	}

	private static final int securityObject = 17;
	private static final int pidSecIaTable = 54;
	private static final int pidSeqSending = 59;

	private static long readSeqSending(final ManagementClientImpl mc, final Destination dst)
			throws KNXTimeoutException, KNXRemoteException, KNXDisconnectException, KNXLinkClosedException,
			InterruptedException {

		logger.log(TRACE, "query sequence number of {0}", dst.getAddress());
		final var desc = mc.readPropertyDescription(dst, securityObject, 1, pidSeqSending, 0);

		int objectIndex = desc.getObjectIndex();
		if (objectIndex == 0) {
			objectIndex = indexByIoList(mc, dst);
			if (objectIndex == 0)
				return -1;
		}

		final byte[] data = mc.readProperty(dst, objectIndex, pidSeqSending, 1, 1);
		return unsigned(data);
	}

	private static long readLastValidSeq(final ManagementClientImpl mc, final Destination dst,
			final IndividualAddress senderAddress) throws KNXTimeoutException, KNXRemoteException,
			KNXDisconnectException, KNXLinkClosedException, InterruptedException {

		logger.log(TRACE, "query {0} for last valid sequence number of {1}", dst.getAddress(), senderAddress);
		final var desc = mc.readPropertyDescription(dst, securityObject, 1, pidSecIaTable, 0);

		int objectIndex = desc.getObjectIndex();
		if (objectIndex == 0) {
			objectIndex = indexByIoList(mc, dst);
			if (objectIndex == 0)
				return -1;
		}

		final int current = desc.getCurrentElements();
		final int elements = current == 0 ? desc.getMaxElements() : current;

		final int key = senderAddress.getRawAddress();
		int low = 1;
		int high = elements;
		while (low <= high) {
			final int mid = (low + high) >>> 1;
			try {
				final byte[] midVal = mc.readProperty(dst, objectIndex, pidSecIaTable, mid, 1);
				final var buffer = ByteBuffer.wrap(midVal);
				final int v = buffer.getShort() & 0xffff;
				final long cmp = v - key;
				if (cmp < 0)
					low = mid + 1;
				else if (cmp > 0)
					high = mid - 1;
				else {
					final byte[] seq = new byte[6];
					buffer.get(seq);
					return unsigned(seq);
				}
			}
			catch (final KNXRemoteException e) {
				high = mid - 1;
			}
		}
		return -1;
	}

	private static int indexByIoList(final ManagementClientImpl mc, final Destination dst) throws KNXTimeoutException,
			KNXRemoteException, KNXDisconnectException, KNXLinkClosedException, InterruptedException {

		final var desc = mc.readPropertyDescription(dst, 0, PropertyAccess.PID.IO_LIST, 0);
		var elems = desc.getCurrentElements();
		if (elems == 0)
			elems = desc.getMaxElements();

		int objectIndex = 0;
		final var data = ByteBuffer.wrap(mc.readProperty(dst, 0, PropertyAccess.PID.IO_LIST, 1, elems));
		while (data.hasRemaining()) {
			final int type = data.getShort() & 0xffff;
			if (type == securityObject)
				break;
			objectIndex++;
		}
		return objectIndex;
	}

	private static long unsigned(final byte[] data) {
		long l = 0;
		for (final byte b : data)
			l = (l << 8) + (b & 0xff);
		return l;
	}
}
