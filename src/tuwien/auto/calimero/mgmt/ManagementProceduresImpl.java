/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2022 B. Malinowsky

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

import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.WARNING;

import java.lang.System.Logger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DetachEvent;
import tuwien.auto.calimero.DeviceDescriptor.DD0;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXRemoteException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.SerialNumber;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.ManagementClient.EraseCode;
import tuwien.auto.calimero.mgmt.ManagementClient.TestResult;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.secure.SecureApplicationLayer;
import tuwien.auto.calimero.secure.Security;

/**
 * An implementation of {@link ManagementProcedures}.
 * <p>
 * In general, invoked procedures should not be run concurrently on the same remote endpoint. As
 * precaution, this implementation will guard against such behavior by executing procedures
 * synchronized on the used management client instance ({@link ManagementClient}) where necessary.
 * Hence, procedures over the same management client instance are executed in sequence. In general,
 * this is not sufficient to guarantee non-concurrent execution of procedures on the same remote
 * endpoint (e.g., one could create more than one management client object). It is the
 * responsibility of the application logic to enforce the necessary limitations.
 *
 * @author B. Malinowsky
 */
public class ManagementProceduresImpl implements ManagementProcedures
{
	private static final int DEVICE_OBJECT_INDEX = 0;

	private static final int DEVICE_DESC_READ = 0x300;
	private static final int DEVICE_DESC_RESPONSE = 0x340;

	// device memory address for programming mode
	private static final int memAddrProgMode = 0x60;
	private static final int defaultApduLength = 15;
	// transport layer connection disconnect timeout [ms]
	private static final int disconnectTimeout = 6000;

	// procedures should synchronize on mc (this also prevents unwanted modifications of
	// procedure timeouts set in mc)
	private final ManagementClient mc;
	private final TransportLayer tl;
	private final boolean detachMgmtAndTransportLayer;

	private static final Logger logger = LogService.getLogger("calimero.mgmt.MgmtProc");

	private static final class TLListener implements TransportListener
	{
		private final Set<IndividualAddress> devices;
		private final Consumer<IndividualAddress> disconnect;
		private final BiConsumer<IndividualAddress, DD0> dd0;
		private final boolean routers;

		private TLListener(final Set<IndividualAddress> scanResult, final boolean scanRouters)
		{
			devices = scanResult;
			disconnect = null;
			dd0 = (__, ___) -> {};
			routers = scanRouters;
		}

		private TLListener(final Consumer<IndividualAddress> onDisconnect,
				final BiConsumer<IndividualAddress, DD0> onDD0, final boolean scanRouters)
		{
			disconnect = onDisconnect;
			dd0 = onDD0;
			devices = null;
			routers = scanRouters;
		}

		@Override
		public void broadcast(final FrameEvent e) {}

		@Override
		public void dataConnected(final FrameEvent e) {
			final var frame = e.getFrame();
			if (frame instanceof CEMILData) {
				final byte[] apdu = frame.getPayload();
				final var source = ((CEMILData) frame).getSource();
				if (DataUnitBuilder.getAPDUService(apdu) == DEVICE_DESC_RESPONSE) {
					try {
						final var dd = DD0.from(Arrays.copyOfRange(apdu, 2, 4));
						dd0.accept(source, dd);
					}
					catch (final RuntimeException rte) { // KNXIllegalArgumentException for unknown DD0
						logger.log(INFO, "{0} device descriptor 0 response", source, rte);
					}
				}
			}
		}

		@Override
		public void dataIndividual(final FrameEvent e) {}

		@Override
		public void disconnected(final Destination d)
		{
			if (d.getDisconnectedBy() != Destination.REMOTE_ENDPOINT)
				return;
			final IndividualAddress addr = d.getAddress();
			if (routers && addr.getDevice() == 0)
				accept(addr);
			else if (!routers && addr.getDevice() != 0)
				accept(addr);
		}

		private void accept(final IndividualAddress addr)
		{
			if (disconnect != null)
				disconnect.accept(addr);
			else
				devices.add(addr);
		}

		@Override
		public void group(final FrameEvent e) {}

		@Override
		public void detached(final DetachEvent e) {}

		@Override
		public void linkClosed(final CloseEvent e) {}
	};

	/**
	 * Creates a new management procedures instance, using the supplied KNX network link.
	 *
	 * @param link the KNX network link in open state, the management procedures instance does not take ownership
	 * @throws KNXLinkClosedException on closed {@link KNXNetworkLink}
	 */
	public ManagementProceduresImpl(final KNXNetworkLink link) throws KNXLinkClosedException {
		tl = new TransportLayerImpl(link);
		mc = new ManagementClientImpl(link, tl);
		detachMgmtAndTransportLayer = true;
	}

	/**
	 * Creates a new management procedures instance, using the supplied KNX network link, and {@code security} for
	 * secure management if required.
	 *
	 * @param link the KNX network link in open state, the management procedures instance does not take ownership
	 * @param security security with device tool keys to use for secure management
	 * @throws KNXLinkClosedException on closed {@link KNXNetworkLink}
	 */
	public ManagementProceduresImpl(final KNXNetworkLink link, final Security security) throws KNXLinkClosedException {
		tl = new TransportLayerImpl(link);
		mc = new ManagementClientImpl(link, new SecureManagement(tl, security.deviceToolKeys()));
		detachMgmtAndTransportLayer = true;
	}

	/**
	 * Creates a new management procedures instance, using the supplied management client
	 * for application layer services.
	 *
	 * @param mgmtClient the management client, with a network link attached and in open state
	 * @param transportLayer the transport layer used to initialize {@code mgmtClient}
	 */
	protected ManagementProceduresImpl(final ManagementClient mgmtClient, final TransportLayer transportLayer) {
		mc = mgmtClient;
		if (!mc.isOpen())
			throw new IllegalStateException("management client not in open state");
		tl = transportLayer;
		detachMgmtAndTransportLayer = false;
	}

	@Override
	public IndividualAddress[] readAddress() throws KNXException, InterruptedException
	{
		synchronized (mc) {
			final var oldTimeout = mc.responseTimeout();
			mc.responseTimeout(Duration.ofSeconds(3));
			try {
				return mc.readAddress(false);
			}
			catch (final KNXTimeoutException e) {
				// Note: we differ from mgmt client behavior, which throws on no responses
				return new IndividualAddress[0];
			}
			finally {
				mc.responseTimeout(oldTimeout);
			}
		}
	}

	@Override
	public void readDomainAddress(final BiConsumer<IndividualAddress, byte[]> device)
		throws KNXException, InterruptedException
	{
		synchronized (mc) {
			final var oldTimeout = mc.responseTimeout();
			mc.responseTimeout(Duration.ofSeconds(3));
			try {
				mc.readDomainAddress(device);
			}
			catch (final KNXTimeoutException e) {}
			finally {
				mc.responseTimeout(oldTimeout);
			}
		}
	}

	private static final int routerObjectType = 6;
	private static final int pidIpSbcControl = 120;

	private static final Supplier<KNXNetworkLink> noLinkSupplier = () -> null;

	public void writeDomainAddress(final SerialNumber serialNumber, final byte[] domainAddress,
			final List<IndividualAddress> knxipRouters) throws KNXException, InterruptedException {
		writeDomainAddress(serialNumber, domainAddress, knxipRouters, noLinkSupplier);
	}

	public void writeDomainAddress(final SerialNumber serialNumber, final byte[] domainAddress,
			final List<IndividualAddress> knxipRouters, final Supplier<KNXNetworkLink> linkSupplier)
					throws KNXException, InterruptedException {

		final var ipSbcEnabled = new ArrayList<Destination>();
		for (final var router : knxipRouters) {
			final var dst = getOrCreateDestination(router);
			try {
				mc.callFunctionProperty(dst, routerObjectType, 1, pidIpSbcControl, (byte) 0, (byte) 1);
				ipSbcEnabled.add(dst);
			}
			catch (KNXDisconnectException | KNXRemoteException e) {
				logger.log(WARNING, "failed to enable IP system broadcast on {0}, {1}", router, e.getMessage());
			}
		}

		try {
			for (int i = 0; i < 2; ++i) {
				mc.writeDomainAddress(serialNumber, domainAddress);

				if (domainAddress.length == 4 || domainAddress.length == 21) {
					if (domainAddress.length == 21) {
						// remote endpoint executes timer sync for new mcast group & key; this nw procedure has no
						// means to observe this reliably, e.g., on a TP network; we shall wait for max. sync time
						// before proceeding
						final int maxRoutingTimerSync = 25_700;
						Thread.sleep(maxRoutingTimerSync);
					}

					Thread.sleep(1000);

					// link supplier might need to update the keys in Security, too, if security mode got enabled
					// in the device by writing a 21 byte DoA
					final KNXNetworkLink supplierLink = linkSupplier.get();
					final var link = supplierLink != null ? supplierLink : ((TransportLayerImpl) tl).link();

					final var mcImpl = (ManagementClientImpl) mc;
					try (var addressChecker = new ManagementClientImpl(link, mcImpl.secureApplicationLayer())) {
						addressChecker.responseTimeout(Duration.ofSeconds(1));
						for (int rep = 0; rep < 60; rep++) {
							try {
								addressChecker.readAddress(serialNumber);
								return;
							}
							catch (final KNXTimeoutException e) {}
						}
					}
				}
				else {
					Thread.sleep(1000);
					try {
						mc.readAddress(serialNumber);
						return;
					}
					catch (final KNXTimeoutException e) {
						Thread.sleep(1000);
					}
				}
			}
		}
		finally {
			for (final var dst : ipSbcEnabled) {
				try {
					mc.callFunctionProperty(dst, routerObjectType, 1, pidIpSbcControl, (byte) 0, (byte) 0);
				}
				catch (KNXDisconnectException | KNXRemoteException ignore) {}
			}
		}
	}

	@Override
	public boolean writeAddress(final IndividualAddress newAddress) throws KNXException,
		InterruptedException
	{
		boolean exists = false;
		try (Destination dst = getOrCreateDestination(newAddress)) {
			mc.readDeviceDesc(dst, 0);
			exists = true;
		}
		catch (final KNXDisconnectException e) {
			// remote endpoint exists, but might not support CO mode, we proceed
		}
		catch (final KNXTimeoutException e) {
			// no remote endpoint answered, we proceed
		}

		boolean setAddr = false;
		synchronized (mc) {
			final var oldTimeout = mc.responseTimeout();
			try (Destination verify = mc.createDestination(newAddress, true)) {
				mc.responseTimeout(Duration.ofSeconds(1));
				// ??? this does not conform to spec, where no max. attempts are given
				// the problem is that we potentially loop forever (which would be correct)
				int attempts = 20;
				int count = 0;
				while (count != 1 && attempts-- > 0) {
					try {
						final IndividualAddress[] list = mc.readAddress(false);
						count = list.length;
						if (count == 1 && !list[0].equals(newAddress))
							setAddr = true;
					}
					catch (final KNXException e) {
						// a device with newAddress exists but is not in programming mode, bail out
						if (exists) {
							logger.log(WARNING, "device exists but is not in programming mode, cancel writing address");
							return false;
						}
					}
					logger.log(INFO, "KNX devices in programming mode: " + count);
				}
				if (!setAddr)
					return false;
				mc.writeAddress(newAddress);
				// if this throws, either programming failed, or its
				// probably some network configuration issue
				mc.readDeviceDesc(verify, 0);
				mc.restart(verify);
			}
			finally {
				mc.responseTimeout(oldTimeout);
			}
		}
		return true;
	}

	@Override
	public void resetAddress() throws KNXException, InterruptedException
	{
		final IndividualAddress def = new IndividualAddress(0xffff);
		try (Destination dst = mc.createDestination(def, true)) {
			while (true) {
				mc.writeAddress(def);
				mc.restart(dst);
				try {
					mc.readAddress(true);
				}
				catch (final KNXTimeoutException e) {
					// no more responses, we're done
					break;
				}
			}
		}
	}

	@Override
	public boolean isAddressOccupied(final IndividualAddress devAddr)
		throws KNXException, InterruptedException
	{
		try (Destination dst = mc.createDestination(devAddr, true)) {
			mc.readDeviceDesc(dst, 0);
		}
		catch (final KNXTimeoutException e) {
			return false;
		}
		catch (final KNXDisconnectException e) {
			// remote disconnect: device with that address exists but does not support CO mode
			if (e.getDestination().getDisconnectedBy() != Destination.REMOTE_ENDPOINT)
				return false;
		}
		return true;
	}

	@Override
	public IndividualAddress readAddress(final SerialNumber serialNo) throws KNXException, InterruptedException {
		return mc.readAddress(serialNo);
	}

	@Override
	public boolean writeAddress(final SerialNumber serialNo, final IndividualAddress newAddress)
			throws KNXException, InterruptedException {
		mc.writeAddress(serialNo, newAddress);
		final IndividualAddress chk = mc.readAddress(serialNo);
		final boolean equals = chk.equals(newAddress);
		if (!equals)
			logger.log(WARNING, "write device address {0}/{1} reported back {2}", serialNo, newAddress, chk);
		return equals;
	}

	/**
	 * Reads the serial number of KNX devices in programming mode.
	 * <p>
	 * This method corresponds to the KNX <i>NM_Read_SerialNumber_By_ProgrammingMode</i><br>.
	 * Depending on whether none, one, or several devices are in programming mode, the
	 * returned list size of addresses is 0, 1, or &gt; 1, respectively.
	 * Impl. note: the read timeout is 1.5 seconds.
	 *
	 * @return a list with {@link SerialNumber}s of devices in programming
	 *         mode, with the list size equal to the number of device responses
	 * @throws KNXLinkClosedException if network link to KNX network is closed
	 * @throws KNXRemoteException on invalid response behavior from a remote endpoint
	 * @throws KNXException and subtypes on other errors
	 * @throws InterruptedException on interrupted thread
	 */
	public List<SerialNumber> readSerialNumber() throws KNXException, InterruptedException {
		final List<byte[]> l = mc.readSystemNetworkParameter(0, PID.SERIAL_NUMBER, 1);
		return l.stream().map(SerialNumber::from).collect(Collectors.toList());
	}

	/**
	 * Reads the serial number of KNX devices in ex-factory state, i.e., devices of which both the domain address
	 * (if available) and the individual address have their factory default value.
	 * <p>
	 * This method corresponds to the KNX <i>NM_Read_SerialNumber_By_ExFactoryState</i><br>.
	 * Depending on whether none, one, or several devices respond, the
	 * returned list size of addresses is 0, 1, or &gt; 1, respectively.
	 *
	 * @return a list with {@link SerialNumber}s of devices in programming
	 *         mode, with the list size equal to the number of device responses
	 * @throws KNXLinkClosedException if network link to KNX network is closed
	 * @throws KNXRemoteException on invalid response behavior from a remote endpoint
	 * @throws KNXException and subtypes on other errors
	 * @throws InterruptedException on interrupted thread
	 */
	public List<SerialNumber> readSerialNumberExFactoryState() throws KNXException, InterruptedException {
		final var waitTime = Duration.ofSeconds(3);
		final List<byte[]> l = mc.readSystemNetworkParameter(0, PID.SERIAL_NUMBER, 2, (byte) waitTime.toSeconds());
		return l.stream().map(SerialNumber::from).collect(Collectors.toList());
	}

	/**
	 * Reads the serial number of KNX devices which have just been powered on, to identify and address "inaccessible
	 * devices".
	 * <p>
	 * This method corresponds to the KNX <i>NM_Read_SerialNumber_By_PowerReset</i> procedure.
	 * Depending on whether none, one, or several devices respond, the
	 * returned list size of addresses is 0, 1, or &gt; 1, respectively. The read timeout is 4 minutes.
	 *
	 * @return a list with {@link SerialNumber}s of devices, with the list size equal to the number of device responses
	 * @throws KNXLinkClosedException if network link to KNX network is closed
	 * @throws KNXRemoteException on invalid response behavior from a remote endpoint
	 * @throws KNXException and subtypes on other errors
	 * @throws InterruptedException on interrupted thread
	 */
	public List<SerialNumber> readSerialNumberPowerReset() throws KNXException, InterruptedException {
		final List<byte[]> l = new ArrayList<>();
		// we have to use mc response timeout, because readSystemNetworkParameter registers services only for that
		// duration, it doesn't consider a higher wait time
		final var waitTime = mc.responseTimeout();

		final long start = System.nanoTime();
		final long stop = start + 4 * 60_000_000_000L;
		long next = start;
		while (next < stop) {
			l.addAll(mc.readSystemNetworkParameter(0, PID.SERIAL_NUMBER, 3, (byte) waitTime.toSeconds()));

			next = next + 30_000_000_000L;
			long millis = (next - System.nanoTime()) / 1_000_000;
			while (millis > 0) {
				Thread.sleep(millis);
				millis = (next - System.nanoTime()) / 1_000_000;
			}
		}
		return l.stream().map(SerialNumber::from).collect(Collectors.toList());
	}

	@Override
	public IndividualAddress[] scanNetworkRouters() throws KNXTimeoutException,
		KNXLinkClosedException, InterruptedException
	{
		final List<IndividualAddress> addresses = new ArrayList<>();
		for (int address = 0x0000; address <= 0xFF00; address += 0x0100)
			addresses.add(new IndividualAddress(address));
		return scanAddresses(addresses, true);
	}

	@Override
	public IndividualAddress[] scanNetworkDevices(final int area, final int line)
		throws KNXTimeoutException, KNXLinkClosedException, InterruptedException
	{
		if (area < 0 || area > 0xf)
			throw new KNXIllegalArgumentException("area out of range [0..0xf]");
		if (line < 0 || line > 0xf)
			throw new KNXIllegalArgumentException("line out of range [0..0xf]");

		final List<IndividualAddress> addresses = new ArrayList<>();
		for (int device = 0; device <= 0xff; ++device) {
			final IndividualAddress remote = new IndividualAddress(area, line, device);
			addresses.add(remote);
		}
		return scanAddresses(addresses, false);
	}

	@Override
	public void scanNetworkDevices(final int area, final int line, final Consumer<IndividualAddress> device,
			final BiConsumer<IndividualAddress, DD0> deviceWithDescriptor) throws KNXLinkClosedException,
			InterruptedException
	{
		if (area < 0 || area > 0xf)
			throw new KNXIllegalArgumentException("area out of range [0..0xf]");
		if (line < 0 || line > 0xf)
			throw new KNXIllegalArgumentException("line out of range [0..0xf]");
		final List<IndividualAddress> addresses = IntStream.rangeClosed(0, 0xff)
				.mapToObj((i) -> new IndividualAddress(area, line, i)).collect(Collectors.toList());
		scanAddresses(addresses, false, device, deviceWithDescriptor);
	}

	@Override
	public List<byte[]> scanSerialNumbers(final int medium) throws KNXException, InterruptedException
	{
		synchronized (mc) {
			final var oldTimeout = mc.responseTimeout();
			try (Destination dst = mc.createDestination(new IndividualAddress(0, medium, 0xff), true)) {
				mc.responseTimeout(Duration.ofSeconds(7));
				return ((ManagementClientImpl) mc).readProperty(dst, 0, PropertyAccess.PID.SERIAL_NUMBER, 1, 1, false);
			}
			catch (final KNXTimeoutException e) {
				// no response is fine
			}
			finally {
				mc.responseTimeout(oldTimeout);
			}
		}
		return Collections.emptyList();
	}

	@Override
	public List<IndividualAddress> scanGroupAddresses(final GroupAddress startAddress, final int range)
			throws KNXException, InterruptedException {
		if (range < 1 || range > 255)
			throw new KNXIllegalArgumentException("range " + range + " not in [1..255]");

		final int addressTableObject = 1;
		final byte[] ga = startAddress.toByteArray();
		final byte[] testInfo = { (byte) range, ga[0], ga[1] };
		final var responses = mc.readNetworkParameter(addressTableObject, PID.TABLE, testInfo);
		return responses.stream().filter(r -> Arrays.equals(testInfo, r.result())).map(TestResult::remote)
				.collect(Collectors.toList());
	}

	@Override
	public void setProgrammingMode(final IndividualAddress device, final boolean programming)
		throws KNXException, InterruptedException
	{
		// conn.oriented
		final Destination d = getOrCreateDestination(device);
		try {
			// at first, try the KNX property to set programming mode
			mc.writeProperty(d, DEVICE_OBJECT_INDEX, PropertyAccess.PID.PROGMODE, 1, 1,
					new byte[] { (byte) (programming ? 0x01 : 0x00) });
			return;
		}
		catch (final KNXException e) {
			logger.log(WARNING, "setting programming mode via property failed, (" + e + "), trying via memory");
		}

		// read from memory where device keeps programming mode
		final byte[] mem = mc.readMemory(d, memAddrProgMode, 1);
		// store lowest 7 bits
		int set = mem[0] & 0x7f;
		// programming mode is at bit 0
		set = programming ? set | 0x1 : set & 0xfe;
		// update to even parity at bit 7 (MSB)
		set = isOddParity(set) ? set | 0x80 : set;
		mem[0] = (byte) set;
		mc.writeMemory(d, memAddrProgMode, mem);
	}

	@Override
	public void writeMemory(final IndividualAddress device, final long startAddress,
		final byte[] data, final boolean verifyWrite, final boolean verifyByServer)
		throws KNXException, InterruptedException
	{
		if (startAddress < 0 || startAddress > 0xffffffffL)
			throw new KNXIllegalArgumentException("start address is no 32 Bit address");

		// either verifyWrite or verifyByServer, not both applicable
		if (verifyWrite && verifyByServer)
			throw new KNXIllegalArgumentException(
				"verify write and verify by server not both applicable");

		final Destination d = getOrCreateDestination(device, false, verifyByServer);
		// if automatic server verification is requested, turn verify flag on
		if (verifyByServer) {
			// reading description checks whether property exists
			/* final byte[] desc = */mc.readPropertyDesc(d, DEVICE_OBJECT_INDEX,
				PropertyAccess.PID.DEVICE_CONTROL, 0);
			final byte[] ctrl = mc.readProperty(d, DEVICE_OBJECT_INDEX,
				PropertyAccess.PID.DEVICE_CONTROL, 1, 1);
			// bit 2 is set for automatic management server verification (responds on
			// memory write with a response containing the written data)
			ctrl[0] |= 0x04;
			mc.writeProperty(d, DEVICE_OBJECT_INDEX, PropertyAccess.PID.DEVICE_CONTROL,
				1, 1, ctrl);
		}

		// create structure to write
		/*
		 Byte structure of data transmitted in ASDUs:
		 | 0    | 1     | 2 3 4 5            | 6 7 8 9      |10 11 12 13 |14..31|
		 | code | flags | dataBlockStartAddr | startAddress | endAddress | data |
		 | 0x20 | ...   | ...                | ...          | ...        | ...  |
		*/
		final int dataBlockStartAddress = 0;
		// int flags = dataBlockStartAddress == 0 ? 0x01 : 0;
		int flags = 0x01;
		flags |= verifyWrite ? 0x02 : 0;
		final long endAddress = startAddress + data.length;

		final int offset = 14;
		final byte[] write = new byte[offset + data.length];
		write[0] = 0x20;
		write[1] = (byte) flags;
		setAddress(write, 2, dataBlockStartAddress);
		setAddress(write, 6, startAddress);
		setAddress(write, 10, endAddress);
		for (int i = 0; i < data.length; ++i)
			write[offset + i] = data[i];

		// write memory in chunks matching the maximum asdu length of the device
		final int asduLength = readMaxAsduLength(d);
		for (int i = 0; i < write.length; i += asduLength) {
			final byte[] range = Arrays.copyOfRange(write, i, i + asduLength);

			// on server verification, our mgmt client will already compare the response value
			mc.writeMemory(d, (int) startAddress + i, range);

			// on manual write verification, we explicitly read back memory
			if (verifyWrite) {
				final byte[] read = mc.readMemory(d, (int) startAddress + i, range.length);
				if (!Arrays.equals(read, range))
					throw new KNXRemoteException("verify failed (memory data differs)");
			}
		}
	}

	@Override
	public byte[] readMemory(final IndividualAddress device, final long startAddress,
		final int bytes) throws KNXException, InterruptedException
	{
		if (startAddress < 0 || startAddress > 0xffffffffL)
			throw new KNXIllegalArgumentException("start address is no 32 Bit address");
		if (bytes < 0)
			throw new KNXIllegalArgumentException("bytes to read require a positive number");
		// sanity check, at least emit a warning
		// if (bytes > 4096)
		// logger.log(WARNING, "reading over 4K of device memory "
		// + "(hope you know what you are doing)");

		final Destination d = getOrCreateDestination(device);

		final byte[] read = new byte[bytes];
		final int asduLength = readMaxAsduLength(d);
		for (int i = 0; i < read.length; i += asduLength) {
			final int size = i + asduLength <= read.length ? asduLength : read.length - i;
			final byte[] range = mc.readMemory(d, (int) startAddress + i, size);
			System.arraycopy(range, 0, read, i, range.length);
		}
		return read;
	}

	public void assignDomainAndDeviceAddress(final byte[] domainAddress, final IndividualAddress deviceAddress,
			final byte[] fdsk, final byte[] toolKey, final Duration maxLookup, final List<IndividualAddress> knxipRouters)
			throws KNXException, InterruptedException {

		final var deadline = Instant.now().plus(maxLookup);
		var list = List.<SerialNumber>of();
		while (Instant.now().isBefore(deadline) && list.isEmpty())
			list = readSerialNumber();
		if (list.size() != 1)
			throw new KNXRemoteException("" + (list.isEmpty() ? "no" : list.size()) + " devices in programming mode");
		final var sno = list.get(0);

		final var link = ((TransportLayerImpl) tl).link();
		final int medium = link.getKNXMedium().getMedium();
		final boolean openMedium = medium == KNXMediumSettings.MEDIUM_PL110 || medium == KNXMediumSettings.MEDIUM_RF;
		final boolean sysBcast = openMedium;

		final SecureManagement sal  = ((ManagementClientImpl) mc).secureApplicationLayer();

		final var result = broadacstSync(sal, sysBcast, sno, fdsk, toolKey);
		final boolean usesFdsk = (boolean) result[0];
		final AutoCloseable removeableKey = (AutoCloseable) result[1];

		if (openMedium) {
			writeDomainAddress(sno, domainAddress, knxipRouters);
		}
		writeAddress(sno, deviceAddress);

		try {
			removeableKey.close();
		}
		catch (final Exception ignore) {}

		sal.security().deviceToolKeys().put(deviceAddress, usesFdsk ? fdsk : toolKey);

		final var dst = getOrCreateDestination(deviceAddress);
		final int pidSecurityMode = 51;
		final int securityObjectType = 17;
		mc.callFunctionProperty(dst, securityObjectType, 1, pidSecurityMode, (byte) 0, (byte) 1);

		if (usesFdsk) {
			final int pidToolKey = 56;
			// mgmt client will update map of device toolkeys to use this toolkey
			mc.writeProperty(dst, securityObjectType, 1, pidToolKey, 1, 1, toolKey);
		}

		// NYI KNX IP Secure setup

		mc.restart(dst, EraseCode.ConfirmedRestart, 0);
	}

	public void assignDomainAndDeviceAddress(final byte[] domainAddress, final IndividualAddress deviceAddress,
			final byte[] fdsk, final byte[] toolKey, final Duration maxLookup) throws KNXException, InterruptedException {
		assignDomainAndDeviceAddress(domainAddress, deviceAddress, fdsk, toolKey, maxLookup, List.of());
	}

	private Object[] broadacstSync(final SecureApplicationLayer sal, final boolean systemBroadcast,
			final SerialNumber serialNo, final byte[] fdsk, final byte[] toolKey) throws KNXException,
			InterruptedException {

		final String errMsg = String.format("sync.req with device S/N %s failed", serialNo);
		final boolean toolAccess = true;
		if (fdsk.length != 0) {
			try {
				final var request = sal.broadcastSyncRequest(serialNo, fdsk, toolAccess, systemBroadcast);
				final var broadcastKey = request.get();
				return new Object[] { true, broadcastKey };
			}
			catch (final ExecutionException e) {
				if (!(e.getCause() instanceof TimeoutException))
					throw new KNXException(errMsg + ", device not using FDSK", e.getCause());
			}
		}

		try {
			final var request = sal.broadcastSyncRequest(serialNo, toolKey, toolAccess, systemBroadcast);
			final var broadcastKey = request.get();
			return new Object[] { false, broadcastKey };
		}
		catch (final ExecutionException e) {
			if (e.getCause() instanceof TimeoutException)
				throw new KNXTimeoutException(errMsg + ", device with unknown key or in ex-factory state");
			throw new KNXException(errMsg, e.getCause());
		}
	}

	@Override
	public void detach()
	{
		if (detachMgmtAndTransportLayer) {
			mc.detach();
			tl.detach();
		}
	}

	// work around for implementation in TL, which unconditionally throws if dst exists
	private Destination getOrCreateDestination(final IndividualAddress device)
	{
		return getOrCreateDestination(device, false, false);
	}

	// work around for implementation in TL, which unconditionally throws if dst exists
	private Destination getOrCreateDestination(final IndividualAddress device,
		final boolean keepAlive, final boolean verifyByServer)
	{
		return tl.destination(device).orElseGet(() -> tl.createDestination(device, true, keepAlive, verifyByServer));
	}

	private IndividualAddress[] scanAddresses(final List<IndividualAddress> addresses,
		final boolean routers) throws KNXTimeoutException, KNXLinkClosedException,
		InterruptedException
	{
		final Set<IndividualAddress> devices = new HashSet<>();
		final TransportListener tll = new TLListener(devices, routers);
		tl.addTransportListener(tll);

		final List<Destination> destinations = new ArrayList<>();
		try {
			for (final Iterator<IndividualAddress> i = addresses.iterator(); i.hasNext();) {
				final IndividualAddress remote = i.next();
				final Destination d = getOrCreateDestination(remote, true, false);
				destinations.add(d);
				tl.connect(d);
				// increased from 100 (the default) to minimize chance of overflow over FT1.2
				waitFor(115);
			}
			// we wait in total (115 + 6000 + 1000 + 100) ms for a possible T-disconnect, taking
			// into account the KNXnet/IP tunneling.req retransmit timeout plus some network delay
			waitFor(disconnectTimeout + 1100);
		}
		finally {
			tl.removeTransportListener(tll);
			for (final Iterator<Destination> i = destinations.iterator(); i.hasNext();) {
				final Destination d = i.next();
				tl.destroyDestination(d);
			}
		}
		final IndividualAddress[] array = devices
				.toArray(new IndividualAddress[devices.size()]);
		return array;
	}

	private void scanAddresses(final List<IndividualAddress> addresses, final boolean routers,
			final Consumer<IndividualAddress> response, final BiConsumer<IndividualAddress, DD0> deviceWithDescriptor)
			throws KNXLinkClosedException, InterruptedException {

		final var connected = new ConcurrentHashMap<IndividualAddress, Destination>();
		final var disconnectedByRemote = new ConcurrentLinkedQueue<IndividualAddress>();
		final Consumer<IndividualAddress> onDisconnect = remote -> {
			if (connected.remove(remote) != null) {
				disconnectedByRemote.add(remote);
				response.accept(remote);
			}
		};

		final var dd0Requests = new ConcurrentHashMap<IndividualAddress, Destination>();
		final BiConsumer<IndividualAddress, DD0> onDD0 = (remote, dd0) -> {
			final var dst = dd0Requests.remove(remote);
			if (dst != null) {
				dst.close();
				deviceWithDescriptor.accept(remote, dd0);
			}
		};

		final TransportListener tll = new TLListener(onDisconnect, onDD0, routers);
		tl.addTransportListener(tll);

		try {
			for (final var address : addresses) {
				final var d = getOrCreateDestination(address, true, false);
				connected.put(address, d);
				try {
					tl.connect(d);
				}
				catch (final KNXTimeoutException e) {
					logger.log(INFO, "connect timeout during address scan for {0}", d);
				}
				// increased from 100 (the default) to minimize chance of overflow over FT1.2
				waitFor(115);

				while (!disconnectedByRemote.isEmpty()) {
					final var ia = disconnectedByRemote.remove();
					final Destination dd0Req = getOrCreateDestination(ia);
					dd0Requests.put(ia, dd0Req);
					sendDD0Read(dd0Req);
				}
			}
			// we wait in total (115 + 6000 + 1000 + 100) ms for a possible T-disconnect, taking
			// into account the KNXnet/IP tunneling.req retransmit timeout plus some network delay
			waitFor(disconnectTimeout + 1100);
		}
		finally {
			tl.removeTransportListener(tll);
			// TODO this is not sufficient in the case getOrCreateDestination throws
			connected.values().forEach(Destination::destroy);
		}
	}

	private void sendDD0Read(final Destination dst) throws KNXLinkClosedException {
		final byte[] apdu = DataUnitBuilder.createLengthOptimizedAPDU(DEVICE_DESC_READ, (byte) 0);
		try {
			tl.sendData(dst, Priority.LOW, apdu);
		}
		catch (final KNXDisconnectException ignore) {}
	}

	private int readMaxAsduLength(final Destination d) throws InterruptedException
	{
		// asdu is 3 bytes shorter than apdu
		try {
			final byte[] data = mc.readProperty(d, DEVICE_OBJECT_INDEX,
				PropertyAccess.PID.MAX_APDULENGTH, 1, 1);
			return toUnsigned(data) - 3;
		}
		catch (final KNXException e) {
			return defaultApduLength - 3;
		}
	}

	private static void waitFor(final int ms) throws InterruptedException
	{
		Thread.sleep(ms);
	}

	private static int toUnsigned(final byte[] data)
	{
		return ((data[0] & 0xff) << 8) | (data[1] & 0xff);
	}

	private static boolean isOddParity(final int bite)
	{
		int parity = bite ^ (bite >> 4);
		parity ^= parity >> 2;
		parity ^= parity >> 1;
		return (parity & 0x1) != 0;
	}

	private static void setAddress(final byte[] data, final int from, final long address)
	{
		for (int i = 0; i < 4; ++i)
			data[from + i] = (byte) (address >> (3 - i) & 0xff);
	}
}
