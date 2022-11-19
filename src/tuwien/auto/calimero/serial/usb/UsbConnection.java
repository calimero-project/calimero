/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2015, 2022 B. Malinowsky

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

package tuwien.auto.calimero.serial.usb;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static java.util.stream.Collectors.flatMapping;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.toUnmodifiableList;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.lang.System.Logger;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.usb.UsbClaimException;
import javax.usb.UsbConfiguration;
import javax.usb.UsbConst;
import javax.usb.UsbDevice;
import javax.usb.UsbDeviceDescriptor;
import javax.usb.UsbDisconnectedException;
import javax.usb.UsbEndpoint;
import javax.usb.UsbException;
import javax.usb.UsbHostManager;
import javax.usb.UsbHub;
import javax.usb.UsbInterface;
import javax.usb.UsbIrp;
import javax.usb.UsbNotActiveException;
import javax.usb.UsbNotClaimedException;
import javax.usb.UsbNotOpenException;
import javax.usb.UsbPipe;
import javax.usb.UsbPlatformException;
import javax.usb.event.UsbPipeDataEvent;
import javax.usb.event.UsbPipeErrorEvent;
import javax.usb.event.UsbPipeEvent;
import javax.usb.event.UsbPipeListener;

import org.usb4java.Context;
import org.usb4java.DescriptorUtils;
import org.usb4java.Device;
import org.usb4java.DeviceDescriptor;
import org.usb4java.DeviceHandle;
import org.usb4java.DeviceList;
import org.usb4java.LibUsb;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.Connection;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DeviceDescriptor.DD0;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXListener;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.internal.Executor;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.serial.ConnectionEvent;
import tuwien.auto.calimero.serial.ConnectionStatus;
import tuwien.auto.calimero.serial.KNXPortClosedException;
import tuwien.auto.calimero.serial.usb.HidReport.BusAccessServerFeature;
import tuwien.auto.calimero.serial.usb.HidReportHeader.PacketType;
import tuwien.auto.calimero.serial.usb.TransferProtocolHeader.BusAccessServerService;
import tuwien.auto.calimero.serial.usb.TransferProtocolHeader.KnxTunnelEmi;
import tuwien.auto.calimero.serial.usb.TransferProtocolHeader.Protocol;

/**
 * KNX USB connection providing EMI data exchange and Bus Access Server Feature service. The implementation for USB is
 * based on javax.usb and usb4java.
 *
 * @author B. Malinowsky
 */
public class UsbConnection implements Connection<HidReport>
{
	/**
	 * Available EMI types and their respective bit value representation.
	 */
	public enum EmiType {
		// ??? The encoding of this enumeration is for the supported EMI types response only.
		// The feature protocol and the active EMI type uses the KnxTunnelEmi encoding.
		Emi1(1 << 0, KnxTunnelEmi.Emi1),
		Emi2(1 << 1, KnxTunnelEmi.Emi2),
		CEmi(1 << 2, KnxTunnelEmi.CEmi);

		static EnumSet<EmiType> fromBits(final int bitfield)
		{
			final EnumSet<EmiType> types = EnumSet.noneOf(EmiType.class);
			for (final EmiType t : EmiType.values())
				if ((bitfield & t.bit) == t.bit)
					types.add(t);
			return types;
		}

		final int bit;
		// the KNX tunneling EMI enumeration values are different!
		public final KnxTunnelEmi emi;

		EmiType(final int bit, final KnxTunnelEmi emi)
		{
			this.bit = bit;
			this.emi = emi;
		}
	};

	// KNX interfaces that use a USB to ? adapter (e.g., USB to serial adapter)
	// this allows us to at least list those devices, although we cannot tell the
	// actual communication port (e.g., /dev/ttyACM0)
	private static final int[] virtualSerialVendorIds = {
		0x03eb // busware TP-UART
	};
	private static final int[] virtualSerialProductIds = {
		0x204b // busware TP-UART
	};

	// maximum reply time for a response service is 1000 ms
	// the additional milliseconds allow for delay of slow interfaces and OS crap
	private static final int tunnelingTimeout = 1000 + 500; // ms

	private static final String logPrefix = "calimero.usb";
	private static final Logger slogger = LogService.getLogger(logPrefix);
	private final Logger logger;
	private final String name;


	private static final Map<Integer, List<Integer>> vendorProductIds = loadKnxUsbVendorProductIds();

	private static Map<Integer, List<Integer>> loadKnxUsbVendorProductIds() {
		try (var is = UsbConnection.class.getResourceAsStream("/knxUsbVendorProductIds")) {
			final var lines = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8)).lines();
			final int[] currentVendor = new int[1];
			return Map.copyOf(lines.filter(s -> !s.startsWith("#") && !s.isBlank())
					.collect(groupingBy(line ->
									line.startsWith("\t") ? currentVendor[0] : (currentVendor[0] = fromHex(line)),
							 flatMapping(UsbConnection::productsIds, toUnmodifiableList()))));
		}
		catch (final IOException | RuntimeException e) {
			slogger.log(WARNING, "failed loading KNX USB vendor:product IDs, autodetection of USB devices won't work", e);
		}
		return Map.of();
	}

	private static Stream<Integer> productsIds(final String line) {
		return line.startsWith("\t") ? List.of(line.split("#")[0].split(",")).stream().map(s -> fromHex(s)) : Stream.of();
	}

	private final EventListeners<KNXListener> listeners;

	private final UsbDevice dev;
	private final UsbInterface knxUsbIf;
	private final UsbPipe out;
	private final UsbPipe in;

	/*
	 Device Feature Service protocol:
	 Device Feature Get is always answered by Device Feature Response
	 Device Feature Get is only sent by the USB bus access client-side
	 Device Feature Set and Info are not answered
	 Device Feature Info is only sent by the USB bus access server-side
	 */

	private final Object responseLock = new Object();
	private HidReport response;

	// TODO Make sure list is not filled with junk data over time, e.g., add timestamp and sweep
	// after > 5 * tunnelingTimeout. Also identify and log unknown entries.
	// Not tested, because partial reports are not used currently
	private final List<HidReport> partialReportList = Collections.synchronizedList(new ArrayList<>());

	private final UsbCallback callback = new UsbCallback();

	private final class UsbCallback implements Runnable, UsbPipeListener
	{
		private volatile boolean close;

		@Override
		public void run()
		{
			try {
				while (!close)
					in.syncSubmit(new byte[64]);

			}
			catch (UsbNotActiveException | UsbNotOpenException | IllegalArgumentException
					| UsbDisconnectedException | UsbException e) {
				if (!close)
					close(CloseEvent.INTERNAL, e.getMessage());
			}
		}

		@Override
		public void errorEventOccurred(final UsbPipeErrorEvent event)
		{
			final byte epaddr = endpointAddress(event);
			final int idx = epaddr & UsbConst.ENDPOINT_NUMBER_MASK;
			final String dir = DescriptorUtils.getDirectionName(epaddr);

			final UsbException e = event.getUsbException();
			logger.log(ERROR, "EP {0} {1} error event for I/O request, {2}", idx, dir, e.toString());
		}

		@Override
		public void dataEventOccurred(final UsbPipeDataEvent event)
		{
			final byte epaddr = endpointAddress(event);
			final int idx = epaddr & UsbConst.ENDPOINT_NUMBER_MASK;
			final String dir = DescriptorUtils.getDirectionName(epaddr);

			final byte[] data = event.getData();
			// with some implementations, we might get a 0-length or unchanged array back, skip further parsing
			if (event.getActualLength() == 0 || Arrays.equals(data, new byte[64])) {
				logger.log(DEBUG, "EP {0} {1} empty I/O request (length {2})", idx, dir, event.getActualLength());
				return;
			}
			try {
				final HidReport r = new HidReport(data);
				logger.log(TRACE, "EP {0} {1} I/O request {2}", idx, dir, DataUnitBuilder
						.toHex(Arrays.copyOfRange(data, 0, r.getReportHeader().getDataLength() + 3), ""));
				final EnumSet<PacketType> packetType = r.getReportHeader().getPacketType();
				final TransferProtocolHeader tph = r.getTransferProtocolHeader();
				if (packetType.contains(PacketType.Partial) || tph == null)
					assemblePartialPackets(r);
				else if (tph.getProtocol() == Protocol.KnxTunnel)
					fireFrameReceived((KnxTunnelEmi) tph.getService(), r.getData());
				else if (tph.getProtocol() == Protocol.BusAccessServerFeature) {
					// check whether we are waiting for a device feature response service
					if (tph.getService() == BusAccessServerService.Response)
						setResponse(r);
					else if (tph.getService() == BusAccessServerService.Info) {
						final BusAccessServerFeature feature = r.getFeatureId();
						logger.log(TRACE, "{0} {1}", feature, DataUnitBuilder.toHex(r.getData(), ""));
					}

					if (r.getFeatureId() == BusAccessServerFeature.ConnectionStatus) {
						final int status = r.getData()[0];
						listeners.dispatchCustomEvent(status == 1 ? ConnectionStatus.Online : ConnectionStatus.Offline);
					}
				}
				else
					logger.log(WARNING, "unexpected service {0}: {1}", tph.getService(), DataUnitBuilder.toHex(data, ""));
			}
			catch (final KNXFormatException | RuntimeException e) {
				logger.log(ERROR, "creating HID class report from {0}", DataUnitBuilder.toHex(data, ""), e);
			}
		}

		private byte endpointAddress(final UsbPipeEvent event)
		{
			final UsbEndpoint ep = event.getUsbPipe().getUsbEndpoint();
			return ep.getUsbEndpointDescriptor().bEndpointAddress();
		}

		void quit()
		{
			close = true;
		}
	}

	static {
		try {
			printDevices();
		}
		catch (final KnxRuntimeException e) {
			slogger.log(ERROR, "Enumerate USB devices, " + e);
		}
		try {
			final StringBuilder sb = new StringBuilder();
			final List<UsbDevice> devices = getKnxDevices();
			for (final UsbDevice d : devices) {
				try {
					sb.append("\n").append(printInfo(d, slogger, " |   "));
				}
				catch (final UsbException ignore) {}
			}
			slogger.log(INFO, "Found {0} KNX USB devices{1}{2}", devices.size(), sb.length() > 0 ? ":" : "",  sb);
		}
		catch (final RuntimeException e) {}
	}

	/**
	 * Scans for USB device connection changes, so subsequent traversals provide an updated view of attached USB
	 * interfaces.
	 *
	 * @throws SecurityException on restricted access to USB services indicated as security violation
	 * @throws UsbException on error with USB services
	 */
	public static void updateDeviceList() throws SecurityException, UsbException
	{
		((org.usb4java.javax.Services) UsbHostManager.getUsbServices()).scan();
	}

	public static List<UsbDevice> getDevices()
	{
		return collect(getRootHub());
	}

	/**
	 * Returns the list of KNX devices currently attached to the host, based on known KNX vendor IDs.
	 *
	 * @return the list of found KNX devices
	 */
	public static List<UsbDevice> getKnxDevices()
	{
		final List<UsbDevice> knx = new ArrayList<>();
		for (final UsbDevice d : getDevices()) {
			final var descriptor = d.getUsbDeviceDescriptor();
			final int vendor = descriptor.idVendor() & 0xffff;
			if (vendorProductIds.getOrDefault(vendor, List.of()).contains(descriptor.idProduct() & 0xffff))
				knx.add(d);
		}
		return knx;
	}

	// internal use only
	public static List<UsbDevice> getVirtualSerialKnxDevices() throws SecurityException
	{
		final List<UsbDevice> knx = new ArrayList<>();
		for (final UsbDevice d : getDevices()) {
			final int vendor = d.getUsbDeviceDescriptor().idVendor() & 0xffff;
			final int product = d.getUsbDeviceDescriptor().idProduct() & 0xffff;
			for (int i = 0; i < virtualSerialVendorIds.length; i++) {
				final int v = virtualSerialVendorIds[i];
				if (v == vendor && virtualSerialProductIds[i] == product)
					knx.add(d);
			}
		}
		return knx;
	}

	public static void printDevices()
	{
		final StringBuilder sb = new StringBuilder();
		traverse(getRootHub(), sb, "");
		slogger.log(DEBUG, "Enumerate USB devices\n{0}", sb);

		// Use the low-level API, because on Windows the string descriptors cause problems
		slogger.log(DEBUG, () -> "Enumerate USB devices using the low-level API\n" +
				getDeviceDescriptionsLowLevel().stream().collect(Collectors.joining("\n")));
	}

	/**
	 * Creates a new KNX USB connection using a KNX USB {@code device} identifier to locate the USB interface,
	 * being either a {@code vendorId:productId}, or a name used for pattern matching with the USB device
	 * descriptor strings.
	 *
	 * @param device a {@code vendorId:productId} identifier, or a name (case-insensitive) that is used to match a
	 *        KNX USB device by its description strings, e.g, "siemens", "busch-jaeger", "abb". Note, that with more
	 *        than one USB device matching the criteria of {@code device}, the first one found is selected
	 * @throws KNXException on errors finding or accessing the USB interface, or opening the KNX USB connection
	 */
	public UsbConnection(final String device) throws KNXException
	{
		this(findDevice(device), device);
	}

	/**
	 * Creates a new KNX USB connection using a vendor and product identifier to locate the USB interface. Note, that
	 * with more than one USB interfaces matching {@code vendorId:productId}, the first one found is selected. This
	 * is only the case if several USB interfaces of the same make and model are attached to the host.
	 *
	 * @param vendorId the vendor identifier of the USB {@code vendorId:productId}
	 * @param productId the product identifier of the USB {@code vendorId:productId}
	 * @throws KNXException on errors finding or accessing the USB interface, or opening the KNX USB connection
	 */
	// TODO we use the first matching USB device we find, current param list is not sufficient!
	public UsbConnection(final int vendorId, final int productId) throws KNXException
	{
		this(findDevice(vendorId, productId), toDeviceId(vendorId, productId));
	}

	private UsbConnection(final UsbDevice device, final String name) throws KNXException
	{
		dev = device;
		this.name = name.isEmpty() ? toDeviceId(device) : name;
		logger = LogService.getLogger(logPrefix + "." + name());
		listeners = new EventListeners<>(logger, ConnectionEvent.class);
		listeners.registerEventType(ConnectionStatus.class);

		try {
			final Object[] usbIfInOut = open(device);

			knxUsbIf = (UsbInterface) usbIfInOut[0];
			// EP address in/out: USB endpoints for asynchronous KNX data transfer over interrupt pipe
			final int epAddressIn = (int) usbIfInOut[1];
			final int epAddressOut = (int) usbIfInOut[2];

			out = open(knxUsbIf, epAddressOut);
			in = open(knxUsbIf, epAddressIn);
			in.addUsbPipeListener(callback);
			// if necessary, unclog the incoming pipe
			UsbIrp irp;
			do {
				irp = in.asyncSubmit(new byte[64]);
				irp.waitUntilComplete(10);
			}
			while (irp.isComplete());

			Executor.execute(callback, "Calimero USB callback");
		}
		catch (UsbNotActiveException | UsbDisconnectedException | UsbNotClaimedException | UsbException e) {
			throw new KNXException("open USB connection '" + this.name + "'", e);
		}
	}

	private static String toDeviceId(final UsbDevice device) {
		final UsbDeviceDescriptor dd = device.getUsbDeviceDescriptor();
		return toDeviceId(dd.idVendor(), dd.idProduct());
	}

	/**
	 * Adds the specified event listener {@code l} to receive events from this connection. If {@code l} was
	 * already added as listener, no action is performed.
	 *
	 * @param l the listener to add
	 */
	@Override
	public void addConnectionListener(final KNXListener l)
	{
		listeners.add(l);
	}

	/**
	 * Removes the specified event listener {@code l}, so it does no longer receive events from this connection. If
	 * {@code l} was not added in the first place, no action is performed.
	 *
	 * @param l the listener to remove
	 */
	@Override
	public void removeConnectionListener(final KNXListener l)
	{
		listeners.remove(l);
	}

	@Override
	public void send(final HidReport frame, final BlockingMode blockingMode)
			throws KNXPortClosedException, KNXTimeoutException {
		send(frame, blockingMode != BlockingMode.NonBlocking);
	}

	@SuppressWarnings("unused")
	public void send(final HidReport report, final boolean blocking) throws KNXPortClosedException, KNXTimeoutException
	{
		try {
			final byte[] data = report.toByteArray();
			logger.log(TRACE, "sending I/O request {0}", DataUnitBuilder
					.toHex(Arrays.copyOfRange(data, 0, report.getReportHeader().getDataLength() + 3), ""));
			out.syncSubmit(data);
		}
		catch (UsbException | UsbNotActiveException | UsbNotClaimedException | UsbDisconnectedException e) {
			close();
			throw new KNXPortClosedException("error sending report over USB", name, e);
		}
	}

	/**
	 * Returns the KNX device descriptor type 0 of the USB interface.
	 *
	 * @return device descriptor type 0
	 * @throws KNXPortClosedException on closed port
	 * @throws KNXTimeoutException on response timeout
	 * @throws InterruptedException on interrupt
	 * @see tuwien.auto.calimero.DeviceDescriptor
	 */
	public final DD0 deviceDescriptor() throws KNXPortClosedException, KNXTimeoutException, InterruptedException {
		return DD0.from((int) toUnsigned(getFeature(BusAccessServerFeature.DeviceDescriptorType0)));
	}

	/**
	 * @return the EMI types supported by the KNX USB device
	 * @throws KNXPortClosedException on closed port
	 * @throws KNXTimeoutException on response timeout
	 * @throws InterruptedException on interrupt
	 */
	public final EnumSet<EmiType> getSupportedEmiTypes()
		throws KNXPortClosedException, KNXTimeoutException, InterruptedException
	{
		return EmiType.fromBits(getFeature(BusAccessServerFeature.SupportedEmiTypes)[1]);
	}

	/**
	 * @return the currently active EMI type in the KNX USB device
	 * @throws KNXPortClosedException on closed port
	 * @throws KNXTimeoutException on response timeout
	 * @throws InterruptedException on interrupt
	 */
	public final EmiType getActiveEmiType() throws KNXPortClosedException, KNXTimeoutException, InterruptedException
	{
		final int bits = (int) toUnsigned(getFeature(BusAccessServerFeature.ActiveEmiType));
		final EnumSet<EmiType> all = EnumSet.allOf(EmiType.class);
		for (final EmiType t : all) {
			if (t.emi.id() == bits)
				return t;
		}
		// TODO would an EmiType element "NotSet" make sense? at least one device I know returns
		// 0 in uninitialized state
		throw new KNXIllegalArgumentException("unspecified EMI type " + bits);
	}

	/**
	 * Sets the active EMI type for communication. Before setting an active EMI type, the supported EMI types should be
	 * checked using {@link #getSupportedEmiTypes()}. If only one EMI type is supported, KNX USB device support for this
	 * method is optional.
	 *
	 * @param active the EMI type to activate for communication
	 * @throws KNXPortClosedException on closed port
	 * @throws KNXTimeoutException on response timeout
	 */
	public final void setActiveEmiType(final EmiType active) throws KNXPortClosedException, KNXTimeoutException
	{
		final HidReport r = HidReport.createFeatureService(BusAccessServerService.Set,
				BusAccessServerFeature.ActiveEmiType, new byte[] { (byte) active.emi.id() });
		send(r, true);
	}

	/**
	 * @return current state of the KNX connection, active/not active
	 * @throws KNXPortClosedException on closed port
	 * @throws KNXTimeoutException on response timeout
	 * @throws InterruptedException on interrupt
	 */
	public final boolean isKnxConnectionActive()
		throws KNXPortClosedException, KNXTimeoutException, InterruptedException
	{
		final int data = getFeature(BusAccessServerFeature.ConnectionStatus)[0];
		return (data & 0x01) == 0x01;
	}

	/**
	 * @return the KNX USB manufacturer code as 16 bit unsigned value
	 * @throws KNXPortClosedException on closed port
	 * @throws KNXTimeoutException on response timeout
	 * @throws InterruptedException on interrupt
	 */
	public final int getManufacturerCode() throws KNXPortClosedException, KNXTimeoutException, InterruptedException
	{
		return (int) toUnsigned(getFeature(BusAccessServerFeature.Manufacturer));
	}

	/**
	 * @return the name of this USB connection, usually in the format {@code <vendorID>:<productID>}
	 */
	@Override
	public final String name()
	{
		return name;
	}

	@Override
	public void close()
	{
		close(CloseEvent.CLIENT_REQUEST, "user request");
	}

	// returns [UsbInterface, Endpoint Address In, Endpoint Address Out]
	private Object[] open(final UsbDevice device) throws UsbException
	{
		logger.log(INFO, printInfo(device, logger, ""));

		final UsbConfiguration configuration = device.getActiveUsbConfiguration();
		@SuppressWarnings("unchecked")
		final List<UsbInterface> interfaces = configuration.getUsbInterfaces();
		UsbInterface useUsbIf = null;
		int epAddressOut = 0;
		int epAddressIn = 0;
		for (final UsbInterface uif : interfaces) {
			@SuppressWarnings("unchecked")
			final List<UsbInterface> settings = uif.getSettings();
			// iterate over all alternate settings this interface provides
			for (final UsbInterface alt : settings) {
				logger.log(TRACE, "Interface {0}, setting {1}", alt,
						alt.getUsbInterfaceDescriptor().bAlternateSetting() & 0xff);
				// KNX USB has a HID class interface
				final int interfaceClassHid = 0x03;
				final byte ifClass = alt.getUsbInterfaceDescriptor().bInterfaceClass();
				if (ifClass != interfaceClassHid)
					logger.log(WARNING, "{0} {1} doesn't look right, no HID class", device, alt);
				else {
					@SuppressWarnings("unchecked")
					final List<UsbEndpoint> endpoints = alt.getUsbEndpoints();
					for (final UsbEndpoint endpoint : endpoints) {
						final byte addr = endpoint.getUsbEndpointDescriptor().bEndpointAddress();

						final int index = addr & UsbConst.ENDPOINT_NUMBER_MASK;
						final String inout = DescriptorUtils.getDirectionName(addr);
						logger.log(TRACE, "EP {0} {1}", index, inout);

						final boolean epIn = (addr & LibUsb.ENDPOINT_IN) != 0;
						if (epIn && epAddressIn == 0)
							epAddressIn = addr & 0xff;
						if (!epIn && epAddressOut == 0)
							epAddressOut = addr & 0xff;
						if (useUsbIf == null && epAddressIn != 0 && epAddressOut != 0)
							useUsbIf = alt;
					}
				}
			}
		}
		logger.log(DEBUG, "Found USB device endpoint addresses OUT 0x{0}, IN 0x{1}", Integer.toHexString(epAddressOut),
				Integer.toHexString(epAddressIn));
		final UsbInterface usbIf = Optional.ofNullable(useUsbIf).orElse(configuration.getUsbInterface((byte) 0));
		try {
			usbIf.claim();
		}
		catch (UsbClaimException | UsbPlatformException e) {
			// At least on Linux, we might have to detach the kernel driver. Strangely,
			// a failed claim presents itself as UsbPlatformException, indicating a busy device.
			// Force unload any kernel USB drivers, might work on Linux/OSX, not on Windows.
			usbIf.claim(forceClaim -> true);
		}
		return new Object [] { usbIf, epAddressIn, epAddressOut };
	}

	private static UsbPipe open(final UsbInterface usbIf, final int endpointAddress)
		throws KNXException, UsbNotActiveException, UsbNotClaimedException, UsbDisconnectedException, UsbException
	{
		final UsbEndpoint epout = usbIf.getUsbEndpoint((byte) endpointAddress);
		if (epout == null)
			throw new KNXException(usbIf.getUsbConfiguration().getUsbDevice() + " contains no KNX USB data endpoint 0x"
					+ Integer.toUnsignedString(endpointAddress, 16));
		final UsbPipe pipe = epout.getUsbPipe();
		pipe.open();
		return pipe;
	}

	private void close(final int initiator, final String reason)
	{
		if (!knxUsbIf.isClaimed())
			return;
		final boolean win = System.getProperty("os.name", "unknown").toLowerCase().contains("win");
		try {
			in.removeUsbPipeListener(callback);
			callback.quit();

			if (out.isOpen()) {
				out.abortAllSubmissions();
				out.close();
			}
			if (in.isOpen()) {
				// TODO this causes our callback thread to quit with exception
				in.abortAllSubmissions();
				in.close();
			}
			String ifname = "" + knxUsbIf.getUsbInterfaceDescriptor().bInterfaceNumber();
			try {
				final String s = knxUsbIf.getInterfaceString();
				if (s != null)
					ifname = s;
			}
			catch (final UnsupportedEncodingException e) {}
			logger.log(TRACE, "release USB interface {0}, active={1}, claimed={2}", ifname, knxUsbIf.isActive(),
					knxUsbIf.isClaimed());
			knxUsbIf.release();
		}
		catch (UsbNotActiveException | UsbNotOpenException | UsbDisconnectedException | UsbException e) {
			// windows always throws "USB error 5: Unable to release interface: Entity not found", avoid noise
			if (win && e instanceof UsbPlatformException)
				logger.log(DEBUG, "close connection, {0}", e.getMessage());
			else
				logger.log(WARNING, "close connection", e);
		}
		finally {
			if (win)
				removeClaimedInterfaceNumberOnWindows();
		}
		listeners.fire(l -> l.connectionClosed(new CloseEvent(this, initiator, reason)));
	}

	// Workaround for usb4java-javax on Windows platforms to always remove the interface number of our USB interface.
	// AbstractDevice does not do that in case libusb returns with an error code from releaseInterface().
	// Subsequent claims of that interface then always fail.
	private void removeClaimedInterfaceNumberOnWindows()
	{
		try {
			final Class<? extends UsbDevice> c = dev.getClass();
			final Class<?> abstractDevice = c.getSuperclass();
			final Field field = abstractDevice.getDeclaredField("claimedInterfaceNumbers");
			field.setAccessible(true);
			final Object set = field.get(dev);
			if (set instanceof Set<?>) {
				@SuppressWarnings("unchecked")
				final Set<Byte> numbers = (Set<Byte>) set;
				numbers.remove(knxUsbIf.getUsbInterfaceDescriptor().bInterfaceNumber());
			}
		}
		catch (final Exception e) {
			// specifically NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException
			logger.log(ERROR, "on removing claimed interface number, subsequent claims might fail!", e);
		}
	}

	private byte[] getFeature(final BusAccessServerFeature feature)
		throws InterruptedException, KNXPortClosedException, KNXTimeoutException
	{
		final HidReport r = HidReport.createFeatureService(BusAccessServerService.Get, feature, new byte[0]);
		send(r, true);
		final HidReport res = waitForResponse();
		return res.getData();
	}

	private HidReport waitForResponse() throws InterruptedException, KNXTimeoutException
	{
		long remaining = tunnelingTimeout;
		final long end = System.currentTimeMillis() + remaining;
		while (remaining > 0) {
			synchronized (responseLock) {
				if (response != null) {
					final HidReport r = response;
					response = null;
					return r;
				}
				responseLock.wait(remaining);
			}
			remaining = end - System.currentTimeMillis();
		}
		throw new KNXTimeoutException("waiting for response");
	}

	private void setResponse(final HidReport response)
	{
		synchronized (responseLock) {
			this.response = response;
			responseLock.notify();
		}
	}

	private void assemblePartialPackets(final HidReport part) throws KNXFormatException
	{
		partialReportList.add(part);
		if (!part.getReportHeader().getPacketType().contains(PacketType.End))
			return;

		final ByteArrayOutputStream data = new ByteArrayOutputStream();
		KnxTunnelEmi emiType = null;
		for (int i = 0; i < partialReportList.size(); i++) {
			final HidReport r = partialReportList.get(i);
			if (r.getReportHeader().getSeqNumber() != i + 1) {
				// unexpected order, ignore complete KNX frame and discard received reports
				final String reports = partialReportList.stream().map(Object::toString)
						.collect(Collectors.joining("]\n\t[", "\t[", "]"));
				logger.log(WARNING, "received out of order HID report (expected seq {0}, got {1}) - ignore complete KNX frame, "
						+ "discard reports:\n{}", i + 1, r.getReportHeader().getSeqNumber(), reports);
				partialReportList.clear();
				return;
			}
			if (r.getReportHeader().getPacketType().contains(PacketType.Start))
				emiType = (KnxTunnelEmi) r.getTransferProtocolHeader().getService();
			final byte[] body = r.getData();
			data.write(body, 0, body.length);
		}
		final byte[] assembled = data.toByteArray();
		logger.log(DEBUG, "assembling KNX data frame from {0} partial packets complete: {1}", partialReportList.size(),
				DataUnitBuilder.toHex(assembled, " "));
		partialReportList.clear();
		fireFrameReceived(emiType, assembled);
	}

	/**
	 * Fires a frame received event ({@link KNXListener#frameReceived(FrameEvent)}) for the supplied EMI
	 * {@code frame}.
	 *
	 * @param frame the EMI1/EMI2/cEMI L-data frame to generate the event for
	 * @throws KNXFormatException on error creating cEMI message
	 */
	private void fireFrameReceived(final KnxTunnelEmi emiType, final byte[] frame) throws KNXFormatException
	{
		logger.log(DEBUG, "received {0} frame {1}", emiType, DataUnitBuilder.toHex(frame, ""));
		final FrameEvent fe;
		// check baos main service and forward frame as raw bytes
		if ((frame[0] & 0xff) == 0xf0)
			fe = new FrameEvent(this, frame);
		else
			fe = emiType == KnxTunnelEmi.CEmi ? new FrameEvent(this, CEMIFactory.create(frame, 0, frame.length))
					: new FrameEvent(this, frame);
		listeners.fire(l -> l.frameReceived(fe));
	}

	private static UsbHub getRootHub()
	{
		try {
			return UsbHostManager.getUsbServices().getRootUsbHub();
		}
		catch (final UsbException | SecurityException e) {
			throw new KnxRuntimeException("Accessing USB root hub", e);
		}
	}

	@SuppressWarnings("unchecked")
	private static List<UsbDevice> getAttachedDevices(final UsbHub hub)
	{
		return hub.getAttachedUsbDevices();
	}

	private static UsbDevice findDevice(final int vendorId, final int productId) throws KNXException
	{
		return findDevice(getRootHub(), vendorId, productId);
	}

	private static UsbDevice findDevice(final UsbHub hub, final int vendorId, final int productId) throws KNXException
	{
		for (final UsbDevice d : getAttachedDevices(hub)) {
			final UsbDeviceDescriptor dd = d.getUsbDeviceDescriptor();
			if ((dd.idVendor() & 0xffff) == vendorId && (dd.idProduct() & 0xffff) == productId)
				return d;
			if (d.isUsbHub()) {
				try {
					return findDevice((UsbHub) d, vendorId, productId);
				}
				catch (final KNXException e) {}
			}
		}
		throw new KNXException(toDeviceId(vendorId, productId) + " not found");
	}

	private static UsbDevice findDevice(final String device) throws KNXException
	{
		try {
			// check vendorId:productId format
			final String[] split = device.split(":", -1);
			if (split.length == 2) {
				try {
					final int vendorId = fromHex(split[0]);
					final int productId = fromHex(split[1]);
					return findDevice(getRootHub(), vendorId, productId);
				}
				catch (final NumberFormatException expected) {}
			}
			// check if device name is a substring in one of the USB device strings
			return findDeviceByNameLowLevel(device);
//			return findDeviceByName(getRootHub(), device.toLowerCase());
		}
		catch (final SecurityException | UsbDisconnectedException e) {
			throw new KNXException("find USB device matching '" + device + "'", e);
		}
	}

	// find device by name using high-level API
	// won't work on Windows, because of libusb overflow error on getting the language descriptor
//	private static UsbDevice findDeviceByName(final UsbHub hub, final String device)
//		throws UsbDisconnectedException, UsbException, KNXException
//	{
//		for (final UsbDevice d : getAttachedDevices(hub)) {
//			try {
//				final String mf = d.getManufacturerString();
//				if (mf != null && mf.toLowerCase().contains(device))
//					return d;
//				final String prod = d.getProductString();
//				if (prod != null && prod.toLowerCase().contains(device))
//					return d;
//			}
//			catch (final UnsupportedEncodingException | UsbException e) {}
//			try {
//				if (d.isUsbHub())
//					return findDeviceByName((UsbHub) d, device);
//			}
//			catch (final KNXException e) {}
//		}
//		throw new KNXException("no USB device found with name '" + device + "'");
//	}

	private static List<UsbDevice> collect(final UsbDevice device)
	{
		final List<UsbDevice> l = new ArrayList<>();
		if (device.isUsbHub())
			getAttachedDevices((UsbHub) device).forEach(d -> l.addAll(collect(d)));
		else
			l.add(device);
		return l;
	}

	private static void traverse(final UsbDevice device, final StringBuilder sb, final String indent)
	{
		try {
			sb.append(printInfo(device, slogger, indent));
		}
		catch (final UsbException e) {
			slogger.log(WARNING, "Accessing USB device, " + e);
		}
		if (device.isUsbHub())
			for (final Iterator<UsbDevice> i = getAttachedDevices((UsbHub) device).iterator(); i.hasNext();)
				traverse(i.next(), sb.append("\n"), indent + (i.hasNext() ? " |   " : "     "));
	}

	private static String printInfo(final UsbDevice device, final Logger l, final String indent) throws UsbException
	{
		final StringBuilder sb = new StringBuilder();
		final UsbDeviceDescriptor dd = device.getUsbDeviceDescriptor();
		final String s = indent.isEmpty() ? "" : indent.substring(0, indent.length() - 5) + " |--";
		// vendor ID is mandatory for KNX USB data interface
		sb.append(s).append(device.toString());

		// virtual devices don't contain string descriptors
		final boolean virtual = device instanceof UsbHub && ((UsbHub) device).isRootUsbHub();
		if (virtual)
			return sb.toString();

		// manufacturer is mandatory for KNX USB data interface
		final byte manufacturer = dd.iManufacturer();
		// product support is optional for KNX USB data interface
		final byte product = dd.iProduct();
		final byte sno = dd.iSerialNumber();
		try {
			String desc = indent;
			if (product != 0)
				desc += "" + trimAtNull(device.getString(product));
			if (manufacturer != 0)
				desc += " (" + trimAtNull(device.getString(manufacturer)) + ")";
			if (!desc.equals(indent))
				sb.append("\n").append(desc);
			if (sno != 0)
				sb.append("\n").append(indent).append("S/N ").append(device.getString(sno));
		}
		catch (final UnsupportedEncodingException e) {
			l.log(ERROR, "Java platform lacks support for the required standard charset UTF-16LE", e);
		}
		catch (final UsbPlatformException e) {
			// Thrown on Win 7/8 (USB error 8) on calling device.getString on most USB interfaces.
			// Therefore, catch it here, but don't issue any error/warning
			l.log(DEBUG, "extracting USB device strings, {0}", e.toString());
		}
		return sb.toString();
	}

	// sometimes the usb4java high-level API returns strings which exceed past the null terminator
	private static String trimAtNull(final String s)
	{
		final int end = s.indexOf((char) 0);
		return end > -1 ? s.substring(0, end) : s;
	}

	// pre: device = vendorId:productId
	private static boolean isKnxInterfaceId(final String device)
	{
		final String[] split = device.split(":", -1);
		try {
			final int vend = fromHex(split[0]);
			final int prod = fromHex(split[1]);
			return vendorProductIds.getOrDefault(vend, List.of()).contains(prod);
		}
		catch (final NumberFormatException ignore) {}
		return false;
	}

	// Cross-platform way to do name lookup for USB devices, using the low-level API.
	// Parse the USB device string descriptions for name, extract the vendor:product ID
	// string. Pass that ID to findDevice. which will do the lookup by ID.
	private static UsbDevice findDeviceByNameLowLevel(final String name) throws KNXException
	{
		final List<String> list = getDeviceDescriptionsLowLevel();
		if (name.isEmpty())
			list.removeIf(i -> !isKnxInterfaceId(i.split("ID |\n")[1]));
		else
			list.removeIf(i -> i.toLowerCase().indexOf(name.toLowerCase()) == -1);
		if (list.isEmpty())
			throw new KNXException("no KNX USB device found" + (name.isEmpty() ? "" : " with name matching '" + name + "'"));

		final String desc = list.get(0);
		final String id = desc.substring(desc.indexOf("ID") + 3, desc.indexOf("\n"));
		return findDevice(id);
	}

	// On Win 7/8/8.1, libusb has a problem with overflows on getting the language descriptor,
	// so we can't read out the device string descriptors.
	// This method avoids any further issues down the road by using the ASCII descriptors.
	private static List<String> getDeviceDescriptionsLowLevel()
	{
		final Context ctx = new Context();
		final int err = LibUsb.init(ctx);
		if (err != 0) {
			slogger.log(ERROR, "LibUsb initialization error {0}: {1}", -err, LibUsb.strError(err));
			return Collections.emptyList();
		}
		try {
			final DeviceList list = new DeviceList();
			final int res = LibUsb.getDeviceList(ctx, list);
			if (res < 0) {
				slogger.log(ERROR, "LibUsb device list error {0}: {1}", -res, LibUsb.strError(res));
				return Collections.emptyList();
			}
			try {
				return StreamSupport.stream(list.spliterator(), false).map(UsbConnection::printInfo)
						.collect(Collectors.toList());
			}
			finally {
				LibUsb.freeDeviceList(list, true);
			}
		}
		finally {
			LibUsb.exit(ctx);
		}
	}

	// libusb low level
	private static String printInfo(final Device device)
	{
		final int bus = LibUsb.getBusNumber(device);
		final int address = LibUsb.getDeviceAddress(device);
		int vendor = 0;
		int product = 0;

		final DeviceDescriptor d = new DeviceDescriptor();
		int err = LibUsb.getDeviceDescriptor(device, d);
		if (err == 0) {
			vendor = d.idVendor() & 0xffff;
			product = d.idProduct() & 0xffff;
		}

		final StringBuilder sb = new StringBuilder();
		final String item = vendor != 0 ? toDeviceId(vendor, product) : "";
		sb.append("Bus ").append(bus).append(" Device ").append(address).append(": ID ").append(item);

		final String ind = "    ";
		final DeviceHandle dh = new DeviceHandle();
		err = LibUsb.open(device, dh);
		if (err == 0) {
			try {
				final String man = LibUsb.getStringDescriptor(dh, d.iManufacturer());
				final String prodname = LibUsb.getStringDescriptor(dh, d.iProduct());
				String desc = ind;
				if (prodname != null)
					desc += prodname;
				if (man != null)
					desc += " (" + man + ")";
				if (!desc.equals(ind))
					sb.append("\n").append(desc);
			}
			finally {
				LibUsb.close(dh);
			}
		}

		String attach = "";
		final Device parent = LibUsb.getParent(device);
		if (parent != null) {
			// ??? not necessary in my understanding of the USB tree structure, the bus
			// has to be the same as the child one's
			final int parentBus = LibUsb.getBusNumber(parent);
			final int parentAddress = LibUsb.getDeviceAddress(parent);
			attach = "Parent Hub " + parentBus + ":" + parentAddress;
		}
		final int port = LibUsb.getPortNumber(device);
		if (port != 0)
			attach += (attach.isEmpty() ? "Attached at port " : ", attached at port ") + port;

		// try to show the full path of port numbers from root for this device
		final ByteBuffer path = ByteBuffer.allocateDirect(8);
        final int result = LibUsb.getPortNumbers(device, path);
		if (result > 0)
			attach += IntStream.range(0, result).map(path::get).mapToObj(Integer::toString)
					.collect(Collectors.joining("/", " (/bus:" + LibUsb.getBusNumber(device) + "/", ")"));

		if (!attach.isEmpty())
			sb.append("\n").append(ind).append(attach);

		final int speed = LibUsb.getDeviceSpeed(device);
		if (speed != LibUsb.SPEED_UNKNOWN)
			sb.append("\n").append(ind).append(DescriptorUtils.getSpeedName(speed)).append(" Speed USB");
		return sb.toString();
	}

	public static Device findDeviceLowLevel(final int vendorId, final int productId)
	{
		final Context ctx = null; // use default context
		int err = LibUsb.init(null);
		if (err != 0) {
			slogger.log(ERROR, "LibUsb initialization error {0}: {1}", -err, LibUsb.strError(err));
			return null;
		}
//		try {
			final DeviceList list = new DeviceList();
			final int res = LibUsb.getDeviceList(ctx, list);
			if (res < 0) {
				slogger.log(ERROR, "LibUsb device list error {0}: {1}", -res, LibUsb.strError(res));
				return null;
			}
			try {
				for (final Device device : list) {
					final DeviceDescriptor d = new DeviceDescriptor();
					err = LibUsb.getDeviceDescriptor(device, d);
					if (err == 0) {
						final int vendor = d.idVendor() & 0xffff;
						final int product = d.idProduct() & 0xffff;
						if (vendor == vendorId && product == productId) {
							LibUsb.refDevice(device);
							return device;
						}
					}
				}
			}
			finally {
				LibUsb.freeDeviceList(list, true);
			}
//		}
//		finally {
			// we can't call exit here, as we return a Device for subsequent usage
//			LibUsb.exit(ctx);
//		}
		return null;
	}

	public static Optional<String> getProductName(final Device device)
	{
		final DeviceDescriptor d = new DeviceDescriptor();
		final DeviceHandle dh = new DeviceHandle();
		if (LibUsb.getDeviceDescriptor(device, d) == 0 && LibUsb.open(device, dh) == 0) {
			try {
				return Optional.ofNullable(LibUsb.getStringDescriptor(dh, d.iProduct()));
			}
			finally {
				LibUsb.close(dh);
			}
		}
		return Optional.empty();
	}

	public static Optional<String> getManufacturer(final Device device)
	{
		final DeviceDescriptor d = new DeviceDescriptor();
		final DeviceHandle dh = new DeviceHandle();
		if (LibUsb.getDeviceDescriptor(device, d) == 0 && LibUsb.open(device, dh) == 0) {
			try {
				return Optional.ofNullable(LibUsb.getStringDescriptor(dh, d.iManufacturer()));
			}
			finally {
				LibUsb.close(dh);
			}
		}
		return Optional.empty();
	}

	private static String toDeviceId(final int vendorId, final int productId)
	{
		return String.format("%04x:%04x", vendorId, productId);
	}

	private static long toUnsigned(final byte[] data)
	{
		if (data.length == 1)
			return (data[0] & 0xff);
		if (data.length == 2)
			return (long) (data[0] & 0xff) << 8 | (data[1] & 0xff);
		return (long) (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | (data[3] & 0xff);
	}

	private static int fromHex(final String hex) { return Integer.valueOf(hex.strip(), 16); }
}
