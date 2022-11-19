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

package tuwien.auto.calimero.mgmt;

import static java.lang.String.format;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.WARNING;
import static java.nio.ByteBuffer.allocate;
import static java.util.stream.Collectors.toList;
import static tuwien.auto.calimero.DataUnitBuilder.createAPDU;
import static tuwien.auto.calimero.DataUnitBuilder.createLengthOptimizedAPDU;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DetachEvent;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXInvalidResponseException;
import tuwien.auto.calimero.KNXRemoteException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.ReturnCode;
import tuwien.auto.calimero.SerialNumber;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.secure.KnxSecureException;
import tuwien.auto.calimero.secure.Security;
import tuwien.auto.calimero.secure.SecurityControl;
import tuwien.auto.calimero.secure.SecurityControl.DataSecurity;

/**
 * Implementation of the management client.
 * <p>
 * Uses {@link TransportLayer} internally for communication, and {@link SecureManagement} for KNX Secure if required.
 * All management service methods invoked after a detach of the network link are allowed
 * to throw {@link IllegalStateException}.
 *
 * @author B. Malinowsky
 */
public class ManagementClientImpl implements ManagementClient
{
	private static final int ADC_READ = 0x0180;
	private static final int ADC_RESPONSE = 0x01C0;

	private static final int AUTHORIZE_READ = 0x03D1;
	private static final int AUTHORIZE_RESPONSE = 0x03D2;

	private static final int DOA_WRITE = 0x3E0;
	private static final int DOA_READ = 0x3E1;
	private static final int DOA_RESPONSE = 0x3E2;
	private static final int DOA_SELECTIVE_READ = 0x3E3;

	private static final int IND_ADDR_READ = 0x0100;
	private static final int IND_ADDR_RESPONSE = 0x0140;
	private static final int IND_ADDR_WRITE = 0xC0;

	private static final int IND_ADDR_SN_READ = 0x03DC;
	private static final int IND_ADDR_SN_RESPONSE = 0x03DD;
	private static final int IND_ADDR_SN_WRITE = 0x03DE;

	private static final int DEVICE_DESC_READ = 0x300;
	private static final int DEVICE_DESC_RESPONSE = 0x340;

	private static final int KEY_WRITE = 0x03D3;
	private static final int KEY_RESPONSE = 0x03D4;

	private static final int MEMORY_READ = 0x0200;
	private static final int MEMORY_RESPONSE = 0x0240;
	private static final int MEMORY_WRITE = 0x0280;

	private static final int PROPERTY_DESC_READ = 0x03D8;
	private static final int PROPERTY_DESC_RESPONSE = 0x03D9;

	private static final int PROPERTY_READ = 0x03D5;
	private static final int PROPERTY_RESPONSE = 0x03D6;
	private static final int PROPERTY_WRITE = 0x03D7;

	private static final int FunctionPropertyExtCommand = 0b0111010100;
	private static final int FunctionPropertyExtStateRead =     0b0111010101;
	private static final int FunctionPropertyExtStateResponse = 0b0111010110;

	private static final int SystemNetworkParamRead = 0b0111001000;
	private static final int SystemNetworkParamResponse = 0b0111001001;
	private static final int SystemNetworkParamWrite = 0b0111001010;

	private static final int NetworkParamRead = 0b1111011010;
	private static final int NetworkParamResponse = 0b1111011011;
	static final int NetworkParamWrite = 0b1111100100;

	private static final int MemoryExtendedWrite = 0b0111111011;
	private static final int MemoryExtendedWriteResponse = 0b0111111100;
	private static final int MemoryExtendedRead = 0b0111111101;
	private static final int MemoryExtendedReadResponse = 0b0111111110;

	private static final int DomainAddressSerialNumberWrite = 0b1111101110;

	// serves as both req and res
	private static final int RESTART = 0x0380;

	private class TLListener implements TransportListener
	{
		TLListener() {}

		@Override
		public void broadcast(final FrameEvent e)
		{
			checkResponse(e);
		}

		@Override
		public void dataConnected(final FrameEvent e)
		{
			checkResponse(e);
		}

		@Override
		public void dataIndividual(final FrameEvent e)
		{
			checkResponse(e);
		}

		@Override
		public void disconnected(final Destination d) {}

		@Override
		public void group(final FrameEvent e) {}

		@Override
		public void detached(final DetachEvent e) {}

		@Override
		public void linkClosed(final CloseEvent e)
		{
			logger.log(DEBUG, "attached link was closed");
		}

		private void checkResponse(final FrameEvent e) {
			try {
				if (isActiveService(e)) {
					synchronized (indications) {
						indications.add(e);
						indications.notifyAll();
					}
				}
				listeners.fire(c -> c.accept(e));
			}
			catch (final RuntimeException rte) {
				final var cemi = e.getFrame();
				final var src = cemi instanceof CEMILData ? ((CEMILData) cemi).getDestination() : "cEMI server";
				logger.log(WARNING, "on indication from {0}", src, rte);
			}
		}
	};

	private static final boolean extMemoryServices = true;

	private final TransportLayer tl;
	private final TLListener tlListener = new TLListener();
	private final SecureManagement sal;
	private final boolean toolAccess = true;

	private final IndividualAddress src;
	private volatile Priority priority = Priority.LOW;
	private volatile Duration responseTimeout = Duration.ofSeconds(5);
	private final Deque<FrameEvent> indications = new ArrayDeque<>();
	private final ConcurrentHashMap<Integer, Long> activeServiceResponses = new ConcurrentHashMap<>();
	private volatile boolean detachTransportLayer;
	private volatile boolean detached;
	private final Logger logger;

	private final EventListeners<Consumer<FrameEvent>> listeners;

	SecureManagement secureApplicationLayer() { return sal; }

	/**
	 * Creates a new management client attached to the supplied KNX network link.
	 * For secure management, {@link Security#defaultInstallation} is used.
	 *
	 * @param link network link used for communication with a KNX network, the client does not take ownership
	 * @throws KNXLinkClosedException if the network link is closed
	 */
	public ManagementClientImpl(final KNXNetworkLink link) throws KNXLinkClosedException
	{
		this(link, new TransportLayerImpl(link));
		detachTransportLayer = true;
	}

	/**
	 * Creates a new management client attached to the supplied KNX network link, using {@code security} for secure
	 * management if required.
	 *
	 * @param link network link used for communication with a KNX network, the client does not take ownership
	 * @param security security with device tool keys to use for secure management
	 * @throws KNXLinkClosedException if the network link is closed
	 */
	public ManagementClientImpl(final KNXNetworkLink link, final Security security) throws KNXLinkClosedException {
		this(link, new SecureManagement(new TransportLayerImpl(link), security.deviceToolKeys()));
		detachTransportLayer = true;
	}

	/**
	 * Creates a new management client attached to the supplied KNX network link, and using the supplied transport layer instance.
	 *
	 * @param link network link used for communication with a KNX network, the client does not take ownership
	 * @param transportLayer transport layer, the client does not take ownership (and won't {@link TransportLayer#detach}
	 *        the link)
	 */
	protected ManagementClientImpl(final KNXNetworkLink link, final TransportLayer transportLayer)
	{
		this(link, new SecureManagement(transportLayer, Security.defaultInstallation().deviceToolKeys()));
	}

	protected ManagementClientImpl(final KNXNetworkLink link, final SecureManagement secureManagement) {
		tl = secureManagement.transportLayer();
		logger = LogService.getLogger("calimero.mgmt.MC " + link.getName());
		src = link.getKNXMedium().getDeviceAddress();
		listeners = new EventListeners<>(logger);
		sal = secureManagement;
		sal.addListener(tlListener);
	}

	/**
	 * Internal API.
	 *
	 * @param onEvent consumer to receive notifications about frame events
	 */
	public final void addEventListener(final Consumer<FrameEvent> onEvent)
	{
		listeners.add(onEvent);
	}

	/**
	 * Internal API.
	 *
	 * @param onEvent consumer to receive notifications about frame events
	 */
	public final void removeEventListener(final Consumer<FrameEvent> onEvent)
	{
		listeners.remove(onEvent);
	}

	@Override
	public Duration responseTimeout() {
		return responseTimeout;
	}

	@Override
	public void responseTimeout(final Duration timeout) {
		if (timeout.isNegative() || timeout.isZero())
			throw new KNXIllegalArgumentException("timeout <= 0");
		responseTimeout = timeout;
	}

	@Override
	public void setPriority(final Priority p)
	{
		priority = p;
	}

	@Override
	public Priority getPriority()
	{
		return priority;
	}

	@Override
	public Destination createDestination(final IndividualAddress remote,
		final boolean connectionOriented, final boolean keepAlive, final boolean verifyMode)
	{
		return tl.createDestination(remote, connectionOriented, keepAlive, verifyMode);
	}

	@Override
	public void writeAddress(final IndividualAddress newAddress) throws KNXTimeoutException,
		KNXLinkClosedException
	{
		tl.broadcast(false, Priority.SYSTEM, createAPDU(IND_ADDR_WRITE, newAddress.toByteArray()));
	}

	@Override
	public IndividualAddress[] readAddress(final boolean oneAddressOnly)
		throws KNXTimeoutException, KNXRemoteException, KNXLinkClosedException, InterruptedException
	{
		final long start = registerActiveService(IND_ADDR_RESPONSE);
		tl.broadcast(false, Priority.SYSTEM, DataUnitBuilder.createLengthOptimizedAPDU(IND_ADDR_READ));
		final List<IndividualAddress> l = new ArrayList<>();
		waitForResponses(IND_ADDR_RESPONSE, 0, 0, start, responseTimeout, oneAddressOnly, (source, data) -> {
			l.add(source);
			return Optional.of(source.toByteArray());
		});
		return l.toArray(IndividualAddress[]::new);
	}

	@Override
	public void writeAddress(final SerialNumber serialNo, final IndividualAddress newAddress)
			throws KNXTimeoutException, KNXLinkClosedException {
		final byte[] apdu = DataUnitBuilder.apdu(IND_ADDR_SN_WRITE).put(serialNo.array()).put(newAddress.toByteArray())
				.putShort(0).putShort(0).build();
		broadcast(serialNo, new IndividualAddress(0), false, Priority.SYSTEM, apdu, false);
	}

	@Override
	public IndividualAddress readAddress(final SerialNumber serialNumber)
			throws KNXTimeoutException, KNXRemoteException, KNXLinkClosedException, InterruptedException {
		final long start = registerActiveService(IND_ADDR_SN_RESPONSE);
		tl.broadcast(false, Priority.SYSTEM, createAPDU(IND_ADDR_SN_READ, serialNumber.array()));
		final byte[] address = waitForResponses(IND_ADDR_SN_RESPONSE, 10, 10, start, responseTimeout, true,
				(source, apdu) -> Arrays.equals(serialNumber.array(), 0, 6, apdu, 2, 8)
						? Optional.of(source.toByteArray()) : Optional.empty()).get(0);
		return new IndividualAddress(address);
	}

	@Override
	public void writeDomainAddress(final byte[] domain) throws KNXTimeoutException, KNXLinkClosedException {
		if (domain.length != 2 && domain.length != 6)
			throw new KNXIllegalArgumentException("invalid length of domain address");
		broadcast(SerialNumber.Zero, new IndividualAddress(0), true, priority, createAPDU(DOA_WRITE, domain), false);
	}

	@Override
	public void writeDomainAddress(final SerialNumber serialNumber, final byte[] domain)
			throws KNXTimeoutException, KNXLinkClosedException {
		if (domain.length != 2 && domain.length != 4 && domain.length != 6 && domain.length != 21)
			throw new KNXIllegalArgumentException("domain address with invalid length " + domain.length);
		final var apdu = DataUnitBuilder.apdu(DomainAddressSerialNumberWrite).put(serialNumber.array()).put(domain).build();
		final boolean requireSecure = domain.length == 21;
		broadcast(serialNumber, new IndividualAddress(0), true, priority, apdu, requireSecure);
	}

	private void broadcast(final SerialNumber serialNumber, final IndividualAddress dst, final boolean systemBcast,
			final Priority p, final byte[] apdu, final boolean requireSecure)
			throws KNXTimeoutException, KNXLinkClosedException {
		try {
			final var securityCtrl = systemBcast ? SecurityControl.SystemBroadcast
					: SecurityControl.of(DataSecurity.AuthConf, true);
			final var tsdu = sal.secureBroadcastData(src, serialNumber, dst, apdu, securityCtrl).orElseGet(() -> {
				if (requireSecure)
					throw new KnxSecureException("broadcast requires data security");
				return apdu;
			});
			tl.broadcast(systemBcast, p, tsdu);
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	@Override
	public List<byte[]> readDomainAddress(final boolean oneDomainOnly)
		throws KNXLinkClosedException, KNXInvalidResponseException, KNXTimeoutException,
		InterruptedException
	{
		// we allow 6 bytes ASDU for RF domains
		return makeDOAs(readBroadcast(priority, DataUnitBuilder.createLengthOptimizedAPDU(DOA_READ), DOA_RESPONSE,
				2, 6, oneDomainOnly));
	}

	@Override
	public void readDomainAddress(final BiConsumer<IndividualAddress, byte[]> response)
		throws KNXLinkClosedException, KNXInvalidResponseException, KNXTimeoutException, InterruptedException
	{
		final long start = registerActiveService(DOA_RESPONSE);
		tl.broadcast(true, priority, DataUnitBuilder.createLengthOptimizedAPDU(DOA_READ));
		try {
			// we allow 6 bytes ASDU for RF domains
			waitForResponses(DOA_RESPONSE, 2, 6, start, responseTimeout, false, (source, apdu1) -> {
				response.accept(source, Arrays.copyOfRange(apdu1, 2, apdu1.length));
				return Optional.of(apdu1);
			});
		}
		catch (final KNXTimeoutException e) {}
	}

	@Override
	public List<byte[]> readDomainAddress(final byte[] domain, final IndividualAddress start,
		final int range) throws KNXInvalidResponseException, KNXLinkClosedException,
		KNXTimeoutException, InterruptedException
	{
		if (domain.length != 2)
			throw new KNXIllegalArgumentException("length of domain address not 2 bytes");
		if (range < 0 || range > 255)
			throw new KNXIllegalArgumentException("range out of range [0..255]");
		final var apdu = DataUnitBuilder.apdu(DOA_SELECTIVE_READ).put(domain).put(start.toByteArray()).put(range).build();
		return makeDOAs(readBroadcast(priority, apdu, DOA_RESPONSE, 2, 2, false));
	}

	@Override
	public List<byte[]> readNetworkParameter(final IndividualAddress remote, final int objectType, final int pid,
		final byte... testInfo)
		throws KNXLinkClosedException, KNXTimeoutException, KNXInvalidResponseException, InterruptedException
	{
		final long start = registerActiveService(NetworkParamResponse);
		sendNetworkParameter(NetworkParamRead, remote, objectType, pid, testInfo);

		final BiFunction<IndividualAddress, byte[], Optional<byte[]>> testResponse = (responder, apdu) -> {
			if (apdu.length < 5)
				return Optional.empty();

			final int receivedIot = (apdu[2] & 0xff) << 8 | (apdu[3] & 0xff);
			final int receivedPid = apdu[4] & 0xff;
			if (apdu.length == 5) {
				final String s = receivedPid == 0xff ? receivedIot == 0xffff ? "object type" : "PID" : "response";
				logger.log(INFO, "network parameter read response from {0} for interface object type {1} "
						+ "PID {}: unsupported {}", responder, objectType, pid, s);
				return Optional.empty();
			}
			return receivedIot == objectType && receivedPid == pid ? Optional.of(apdu) : Optional.empty();
		};

		try {
			final List<byte[]> responses = waitForResponses(NetworkParamResponse, 3, 14, start, responseTimeout,
					false, testResponse);
			final int prefix = 2 + 3 + testInfo.length;
			return responses.stream().map(r -> Arrays.copyOfRange(r, prefix, r.length)).collect(toList());
		}
		catch (final KNXTimeoutException e) {
			return List.of();
		}
	}

	@Override
	public List<TestResult> readNetworkParameter(final int objectType, final int pid, final byte... testInfo)
			throws KNXLinkClosedException, KNXTimeoutException, KNXInvalidResponseException, InterruptedException	{
		final long start = registerActiveService(NetworkParamResponse);
		sendNetworkParameter(NetworkParamRead, null, objectType, pid, testInfo);

		final var responses = new ArrayList<TestResult>();
		final BiFunction<IndividualAddress, byte[], Optional<byte[]>> testResponse = (responder, apdu) -> {
			if (apdu.length < 5)
				return Optional.empty();

			final int receivedIot = (apdu[2] & 0xff) << 8 | (apdu[3] & 0xff);
			final int receivedPid = apdu[4] & 0xff;
			if (apdu.length == 5) {
				final String s = receivedPid == 0xff ? receivedIot == 0xffff ? "object type" : "PID" : "response";
				logger.log(INFO, "network parameter read response from {0} for interface object type {1} "
						+ "PID {}: unsupported {}", responder, objectType, pid, s);
				return Optional.empty();
			}
			if (receivedIot == objectType && receivedPid == pid) {
				final int prefix = 2 + 3 + testInfo.length;
				final byte[] testResult = Arrays.copyOfRange(apdu, prefix, apdu.length);
				responses.add(new TestResult(responder, testResult));
				return Optional.of(apdu);
			}
			return Optional.empty();
		};

		try {
			waitForResponses(NetworkParamResponse, 3, 14, start, responseTimeout, false, testResponse);
			return responses;
		}
		catch (final KNXTimeoutException e) {
			return List.of();
		}
	}

	@Override
	public void writeNetworkParameter(final IndividualAddress remote, final int objectType, final int pid,
		final byte... value) throws KNXLinkClosedException, KNXTimeoutException
	{
		sendNetworkParameter(NetworkParamWrite, remote, objectType, pid, value);
	}

	private void sendNetworkParameter(final int apci, final IndividualAddress remote, final int objectType,
		final int pid, final byte[] value) throws KNXTimeoutException, KNXLinkClosedException
	{
		if (objectType < 0 || objectType > 0xffff || pid < 0 || pid > 0xff)
			throw new KNXIllegalArgumentException("IOT or PID argument out of range");
		final byte[] asdu = new byte[3 + value.length];
		asdu[0] = (byte) (objectType >> 8);
		asdu[1] = (byte) objectType;
		asdu[2] = (byte) pid;
		for (int i = 0; i < value.length; i++)
			asdu[3 + i] = value[i];

		final Priority p = Priority.SYSTEM;
		final byte[] tsdu = createAPDU(apci, asdu);
		if (remote != null)
			tl.sendData(remote, p, tsdu);
		else
			tl.broadcast(true, p, tsdu);
	}

	@Override
	public List<byte[]> readSystemNetworkParameter(final int objectType, final int pid, final int operand,
		final byte... additionalTestInfo) throws KNXException, InterruptedException {

		if (operand < 0 || operand > 0xfe)
			throw new KNXIllegalArgumentException("operand out of range");
		final byte[] testInfo = allocate(1 + additionalTestInfo.length).put((byte) operand)
				.put(additionalTestInfo).array();

		final long start = registerActiveService(SystemNetworkParamResponse);
		sendSystemNetworkParameter(SystemNetworkParamRead, objectType, pid, testInfo);

		final BiFunction<IndividualAddress, byte[], Optional<byte[]>> testParamType = (responder, apdu) -> {
			if (apdu.length < 6)
				return Optional.empty();
			final int receivedIot = (apdu[2] & 0xff) << 8 | (apdu[3] & 0xff);
			final int receivedPid = (apdu[4] & 0xff) << 4 | (apdu[5] & 0xf0) >> 4;
			if (apdu.length == 6) {
				final String s = receivedPid == 0xff ? receivedIot == 0xffff ? "object type" : "PID" : "response";
				logger.log(INFO, "system network parameter read response from {0} for interface object type {1} "
						+ "PID {}: unsupported {}", responder, objectType, pid, s);
				return Optional.empty();
			}
			final int receivedOperand = apdu[6] & 0xff;
			return receivedIot == objectType && receivedPid == pid && receivedOperand == operand ? Optional.of(apdu)
					: Optional.empty();
		};

		final Duration waitTime = Duration.ofSeconds(
				operand == 1 ? 1 : operand == 2 || operand == 3 ? additionalTestInfo[0] & 0xff
						: responseTimeout().toSeconds())
				.plusMillis(500); // allow some communication overhead (medium access & device delay times)

		try {
			final List<byte[]> responders = waitForResponses(SystemNetworkParamResponse, 4, 12, start,
					waitTime, false, testParamType);
			final int prefix = 2 + 4 + 1 + additionalTestInfo.length;
			return responders.stream().map(r -> Arrays.copyOfRange(r, prefix, r.length)).collect(toList());
		}
		catch (final KNXTimeoutException e) {
			return List.of();
		}
	}

	@Override
	public void writeSystemNetworkParameter(final int objectType, final int pid, final byte... value)
			throws KNXLinkClosedException, KNXTimeoutException {
		sendSystemNetworkParameter(SystemNetworkParamWrite, objectType, pid, value);
	}

	private void sendSystemNetworkParameter(final int apci, final int objectType, final int pid, final byte[] value)
		throws KNXTimeoutException, KNXLinkClosedException {
		if (objectType < 0 || objectType > 0xffff || pid < 0 || pid > 0xfff)
			throw new KNXIllegalArgumentException("IOT or PID argument out of range");

		final byte[] asdu = allocate(4 + value.length).putShort((short) objectType).putShort((short) (pid << 4))
				.put(value).array();

		final byte[] tsdu = createAPDU(apci, asdu);
		tl.broadcast(true, Priority.SYSTEM, tsdu);
	}

	@Override
	public byte[] readDeviceDesc(final Destination dst, final int descType)
		throws KNXInvalidResponseException, KNXDisconnectException, KNXTimeoutException,
		KNXLinkClosedException, InterruptedException
	{
		if (descType < 0 || descType > 63)
			throw new KNXIllegalArgumentException("descriptor type out of range [0..63]");
		final byte[] apdu = sendWait(dst, priority, DataUnitBuilder.createLengthOptimizedAPDU(
				DEVICE_DESC_READ, new byte[] { (byte) descType }), DEVICE_DESC_RESPONSE, 2, 14);
		final byte[] dd = new byte[apdu.length - 2];
		for (int i = 0; i < apdu.length - 2; ++i)
			dd[i] = apdu[2 + i];
		return dd;
	}

	@Override
	public void restart(final Destination dst) throws KNXTimeoutException, KNXLinkClosedException, InterruptedException
	{
		try {
			restart(true, dst, null, 0);
		}
		catch (KNXRemoteException | KNXDisconnectException ignore) {}
	}

	@Override
	public Duration restart(final Destination dst, final EraseCode eraseCode, final int channel) throws KNXTimeoutException,
			KNXRemoteException, KNXDisconnectException, KNXLinkClosedException, InterruptedException {
		return restart(false, dst, eraseCode, channel);
	}

	// for erase codes 1,3,4 the channel should be 0
	private Duration restart(final boolean basic, final Destination dst, final EraseCode eraseCode,
		final int channel) throws KNXTimeoutException, KNXRemoteException, KNXDisconnectException,
		KNXLinkClosedException, InterruptedException
	{
		int time = 0;
		if (basic) {
			send(dst, priority, DataUnitBuilder.createLengthOptimizedAPDU(RESTART));
		}
		else {
			final byte[] sdu = new byte[] { 0x01, (byte) eraseCode.code(), (byte) channel, };
			final byte[] send = DataUnitBuilder.createLengthOptimizedAPDU(RESTART, sdu);
			final byte[] apdu = sendWait(dst, priority, send, RESTART, 3, 3);
			// check we get a restart response
			if ((apdu[1] & 0x32) == 0)
				throw new KNXInvalidResponseException("restart response bit not set");
			// defined error codes: 0,1,2,3
			final String[] codes = new String[] { "Success", "Access Denied",
				"Unsupported Erase Code", "Invalid Channel Number", "Unknown Error" };
			final int error = Math.min(apdu[2] & 0xff, 4);
			if (error > 0)
				throw new KNXRemoteException("master reset: " + codes[error]);
			time = ((apdu[3] & 0xff) << 8) | (apdu[4] & 0xff);
		}

		if (dst.isConnectionOriented()) {
			// a remote endpoint is allowed to not send a TL disconnect before restart, but
			// a TL disconnect timeout shall not be treated as protocol error
			final Object lock = new Object();
			final TransportListener l = new TLListener()
			{
				@Override
				public void disconnected(final Destination d)
				{
					if (d.equals(dst))
						synchronized (lock) {
							lock.notify();
						}
				};
			};
			tl.addTransportListener(l);
			try {
				synchronized (lock) {
					while (dst.getState() != Destination.State.Disconnected)
						lock.wait();
				}
			}
			finally {
				tl.removeTransportListener(l);
			}
			// always force a disconnect from our side
			tl.disconnect(dst);
		}
		return Duration.ofSeconds(time);
	}

	@Override
	public byte[] readProperty(final Destination dst, final int objIndex, final int propertyId,
		final int start, final int elements) throws KNXTimeoutException, KNXRemoteException,
		KNXDisconnectException, KNXLinkClosedException, InterruptedException
	{
		return readProperty(dst, objIndex, propertyId, start, elements, true).get(0);
	}

	List<byte[]> readProperty(final Destination dst, final int objIndex, final int propertyId, final int start,
		final int elements, final boolean oneResponseOnly) throws KNXTimeoutException, KNXRemoteException,
			KNXDisconnectException, KNXLinkClosedException, InterruptedException {
		if (objIndex < 0 || objIndex > 255 || propertyId < 0 || propertyId > 255
			|| start < 0 || start > 0xFFF || elements < 0 || elements > 15)
			throw new KNXIllegalArgumentException(String.format("argument value out of range: "
					+ "OI 0 < %d < 256, PID 0 < %d < 256, start 0 < %d < 256, elems 0 < %d < 16",
					objIndex, propertyId, start, elements));

		final int maxAsduLength = maxAsduLength(dst);

		int elemsInAsdu = elements;
		if (elements > 1) {
			final var data = readPropertyDesc(dst, objIndex, propertyId, 0);
			final var desc = new Description(0, data);
			final int typeSize = Math.max(8, PropertyTypes.bitSize(desc.getPDT()).orElse(8)) / 8;
			elemsInAsdu = (maxAsduLength - 4) / typeSize;
		}

		final List<byte[]> responses = new ArrayList<>();
		final List<KNXRemoteException> exceptions = new ArrayList<>();

		for (int i = 0; i < elements; i += elemsInAsdu) {
			final int queryElements = Math.min(elemsInAsdu, elements - i);
			final var send = DataUnitBuilder.apdu(PROPERTY_READ).put(objIndex).put(propertyId)
					.put((queryElements << 4) | (((start + i) >>> 8) & 0xF)).put(start + i).build();
			final long startSend = send(dst, priority, send, PROPERTY_RESPONSE);

			final BiFunction<IndividualAddress, byte[], Optional<byte[]>> responseFilter = (source, apdu) -> {
				try {
					if (source.equals(dst.getAddress())) {
						responses.add(extractPropertyElements(apdu, objIndex, propertyId, queryElements));
						return Optional.of(apdu);
					}
				}
				catch (final KNXInvalidResponseException e) {
					logger.log(DEBUG, "skip invalid property read response: {0}", e.getMessage());
				}
				catch (final KNXRemoteException e) {
					exceptions.add(e);
					return Optional.of(new byte[0]); // return empty token to exit waitForResponses
				}
				return Optional.empty();
			};
			waitForResponses(PROPERTY_RESPONSE, 4, maxAsduLength, startSend, responseTimeout, oneResponseOnly,
					responseFilter);
		}

		if (responses.isEmpty()) {
			if (exceptions.size() == 1)
				throw exceptions.get(0);
			final KNXRemoteException e = new KNXRemoteException(
					"reading property " + dst.getAddress() + " OI " + objIndex + " PID " + propertyId + " failed");
			if (exceptions.size() > 0)
				exceptions.forEach(e::addSuppressed);
			throw e;
		}
		if (oneResponseOnly) {
			final var baos = new ByteArrayOutputStream();
			responses.forEach(baos::writeBytes);
			return List.of(baos.toByteArray());
		}
		return responses;
	}

	@Override
	public void writeProperty(final Destination dst, final int objIndex, final int propertyId, final int start,
		final int elements, final byte[] data) throws KNXTimeoutException, KNXRemoteException, KNXDisconnectException,
			KNXLinkClosedException, InterruptedException {
		if (objIndex < 0 || objIndex > 255 || propertyId < 0 || propertyId > 255 || start < 0
				|| start > 0xFFF || data.length == 0 || elements < 0 || elements > 15)
			throw new KNXIllegalArgumentException("argument value out of range");
		final byte[] asdu = new byte[4 + data.length];
		asdu[0] = (byte) objIndex;
		asdu[1] = (byte) propertyId;
		asdu[2] = (byte) ((elements << 4) | ((start >>> 8) & 0xF));
		asdu[3] = (byte) start;
		for (int i = 0; i < data.length; ++i)
			asdu[4 + i] = data[i];
		final byte[] send = createAPDU(PROPERTY_WRITE, asdu);
		final byte[] apdu = sendWait(dst, priority, send, PROPERTY_RESPONSE, 4, maxAsduLength(dst));
		// if number of elements is 0, remote app had problems
		final int elems = (apdu[4] & 0xFF) >> 4;
		if (elems == 0)
			throw new KNXRemoteException("property write failed/forbidden");
		if (elems != elements)
			throw new KNXInvalidResponseException("number of elements differ");
		if (data.length != apdu.length - 6)
			throw new KNXInvalidResponseException("data lengths differ, bytes: "
				+ data.length + " written, " + (apdu.length - 6) + " response");
		// explicitly read back written properties
		for (int i = 4; i < asdu.length; ++i)
			if (apdu[2 + i] != asdu[i])
				throw new KNXRemoteException("read back failed (erroneous property data)");
	}

	private static final int PropertyExtWrite = 0b0111001110;
	private static final int PropertyExtWriteResponse = 0b0111001111;

	@Override
	public void writeProperty(final Destination dst, final int objectType, final int objectInstance,
			final int propertyId, final int start, final int elements, final byte[] data) throws KNXException,
			InterruptedException {

		final long startSend = sendProperty(PropertyExtWrite, PropertyExtWriteResponse, dst, objectType, objectInstance,
				propertyId, start, elements, data);

		final BiFunction<IndividualAddress, byte[], Optional<byte[]>> responseFilter = (responder, apdu) -> {
			if (!responder.equals(dst.getAddress()) || apdu.length != 11)
				return Optional.empty();
			final int receivedIot = (apdu[2] & 0xff) << 8 | (apdu[3] & 0xff);
			final int receivedObjInst = (apdu[4] & 0xff) << 4 | (apdu[5] & 0xf0) >> 4;
			final int receivedPid = (apdu[5] & 0xf) << 8 | apdu[6] & 0xff;
			final int receivedStart = (apdu[8] & 0xff) << 8 | apdu[9] & 0xff;
			return receivedIot == objectType && receivedObjInst == objectInstance && receivedPid == propertyId
					&& receivedStart == start ? Optional.of(apdu) : Optional.empty();
		};

		final var response = waitForResponses(PropertyExtWriteResponse, 9, 9, startSend, responseTimeout, true,
				responseFilter);
		final var returnCode = ReturnCode.of(response.get(0)[8] & 0xff);
		if (returnCode != ReturnCode.Success)
			throw new KNXRemoteException(format("write property response for %d(%d)|%d: %s",
					objectType, objectInstance, propertyId, returnCode.friendly()));
	}

	private long sendProperty(final int svc, final int svcRes, final Destination dst, final int objectType,
			final int objectInstance, final int propertyId, final int start, final int elements, final byte[] data)
			throws KNXTimeoutException, KNXDisconnectException, KNXLinkClosedException, InterruptedException {

		if (objectType < 0 || objectType > 0xffff || propertyId < 0 || propertyId > 0xfff || start < 0 || start > 0xffff
				|| elements < 0 || elements > 255 || data.length == 0)
			throw new KNXIllegalArgumentException("argument value out of range");

		final int securityObjectType = 17;
		final int pidToolKey = 56;
		final var deviceToolKeys = sal.security().deviceToolKeys();
		byte[] updateToolKey = null;
		byte[] oldToolKey = null;
		if (objectType == securityObjectType && objectInstance == 1 && propertyId == pidToolKey) {
			updateToolKey = data.clone();
			oldToolKey = deviceToolKeys.get(dst.getAddress());
		}

		final var apdu = DataUnitBuilder.apdu(svc).putShort(objectType)
				.putShort((objectInstance << 4) | propertyId >> 8).put(propertyId).put(elements).putShort(start)
				.put(data).build();
		try {
			final long s = send(dst, priority, apdu, svcRes, updateToolKey);
			updateToolKey = oldToolKey;
			return s;
		}
		catch (KNXException | InterruptedException | RuntimeException e) {
			if (updateToolKey != null) {
				final var toolKey = oldToolKey;
				deviceToolKeys.compute(dst.getAddress(), (__, ___) -> toolKey);
			}
			throw e;
		}
		finally {
			if (updateToolKey != null)
				Arrays.fill(updateToolKey, (byte) 0);
		}
	}

	private static final int PropertyExtDescRead = 0b0111010010;
	private static final int PropertyExtDescResponse = 0b0111010011;

	private int[] getOrQueryInterfaceObjectList(final Destination dst)
			throws KNXTimeoutException, KNXDisconnectException, KNXLinkClosedException, InterruptedException {
		final Optional<int[]> opt = dst.interfaceObjectList();
		if (opt.isPresent())
			return opt.get();
		int[] list = {};
		try {
			final int elems = unsigned(readProperty(dst, 0, PID.IO_LIST, 0, 1));
			list = new int[elems];
			// NYI use bigger stride based on supported apdu length
			for (int i = 0; i < list.length; i++)
				list[i] = unsigned(readProperty(dst, 0, PID.IO_LIST, i + 1, 1));
		}
		catch (final KNXRemoteException e) {
			logger.log(DEBUG, "device {0} does not support extended property services ({1})", dst.getAddress(), e.toString());
		}
		dst.setInterfaceObjectList(list);
		return list;
	}

	private static int unsigned(final byte[] data) {
		int i = 0;
		for (final byte b : data)
			i = i << 8 | b & 0xff;
		return i;
	}

	@Override
	public Description readPropertyDescription(final Destination dst, final int objectType, final int objInstance,
			final int propertyId, final int propertyIndex) throws KNXTimeoutException, KNXRemoteException,
			KNXDisconnectException, KNXLinkClosedException, InterruptedException {

		if (objectType < 0 || objectType > 0xffff || objInstance < 0 || objInstance > 0xfff || propertyId < 0
				|| propertyId > 0xfff || propertyIndex < 0 || propertyIndex > 0xfff)
			throw new KNXIllegalArgumentException("argument value out of range");

		final int propDescType = 0;
		final int pidx = propertyId != 0 ? 0 : propertyIndex;
		final byte[] send = DataUnitBuilder.apdu(PropertyExtDescRead).putShort(objectType).put(objInstance >> 4)
				.putShort(((objInstance & 0xf) << 12) | propertyId).putShort((propDescType << 12) | pidx).build();

		for (int i = 0; i < 2; i++) {
			final byte[] apdu = sendWait(dst, priority, send, PropertyExtDescResponse, 15, 15);
			final int rcvPropertyId = (((apdu[5] & 0xf) << 8) | (apdu[6] & 0xff));
			final int rcvPropDescType = (apdu[7] >> 4) & 0xf;
			final int rcvPropertyIdx = (((apdu[7] & 0xf) << 8) | (apdu[8] & 0xff));

			final int rcvObjectType = (apdu[2] & 0xff) << 8 | apdu[3] & 0xff;
			// make sure the response contains the requested description
			final boolean objTypeOk = objectType == rcvObjectType;
			final int rcvObjInstance = (apdu[4] & 0xff) << 4 | (apdu[5] & 0xf0) >> 4;
			final boolean oiOk = objInstance == rcvObjInstance;
			final boolean pidOk = propertyId == 0 || propertyId == rcvPropertyId;
			final boolean pidxOk = propertyId != 0 || propertyIndex == rcvPropertyIdx;

			final int dptMain = (apdu[9] & 0xff) << 8 | apdu[10] & 0xff;
			final int dptSub = (apdu[11] & 0xff) << 8 | apdu[12] & 0xff;
			final boolean writeable = (apdu[13] & 0x80) == 0x80;
			final int pdt = apdu[13] & 0x2f;
			final int maxElems = (apdu[14] & 0xff) << 8 | apdu[15] & 0xff;
			final int readLevel = (apdu[16] & 0xf0) >> 4;
			final int writeLevel = apdu[16] & 0xf;
			if (rcvPropDescType == 0 && dptMain == 0 && dptSub == 0 && !writeable && pdt == 0 && maxElems == 0
					&& readLevel == 0 && writeLevel == 0) {
				throw new KNXRemoteException("problem with property description request (IOT or PID non-existant?)");
			}

			if (rcvPropDescType != 0)
				throw new KNXRemoteException("property description type " + rcvPropDescType + " not supported");

			if (objTypeOk && oiOk && pidOk && pidxOk)
				return Description.of(0, Arrays.copyOfRange(apdu, 2, apdu.length));

			logger.log(WARNING, "wrong description response for {0}({1})|{2} prop idx {3} (got {4}({5})|{6} (idx {7}))",
					objectType, objInstance, propertyId, propertyIndex, rcvObjectType, rcvObjInstance, rcvPropertyId,
					rcvPropertyIdx);
		}
		throw new KNXTimeoutException("timeout occurred while waiting for data response");
	}

	private Description readPropertyExtDescription(final Destination dst, final int objIndex, final int propertyId,
			final int propIndex) throws KNXTimeoutException, KNXRemoteException, KNXDisconnectException,
			KNXLinkClosedException, InterruptedException {
		if (objIndex < 0 || objIndex > 0xfff || propertyId < 0 || propertyId > 0xfff || propIndex < 0 || propIndex > 0xfff)
			throw new KNXIllegalArgumentException("argument value out of range");

		final var ioList = getOrQueryInterfaceObjectList(dst);
		if (!(ioList.length > objIndex))
			return null;

		final int objType = ioList[objIndex];
		final int objInstance = 1;

		return readPropertyDescription(dst, objType, objInstance, propertyId, propIndex);
	}

	@Override
	public Description readPropertyDescription(final Destination dst, final int objIndex, final int propertyId,
			final int propertyIndex) throws KNXTimeoutException, KNXRemoteException, KNXDisconnectException,
			KNXLinkClosedException, InterruptedException {
		return new Description(0, readPropertyDesc(dst, objIndex, propertyId, propertyIndex));
	}

	private static final boolean useExtPropertyServices = false;

	@Override
	public byte[] readPropertyDesc(final Destination dst, final int objIndex, final int propertyId, final int propIndex)
		throws KNXTimeoutException, KNXRemoteException, KNXDisconnectException, KNXLinkClosedException,
			InterruptedException {
		if (useExtPropertyServices) {
			final var desc = readPropertyExtDescription(dst, objIndex, propertyId, propIndex);
			if (desc != null)
				return desc.toByteArray();
		}

		if (objIndex < 0 || objIndex > 255 || propertyId < 0 || propertyId > 255 || propIndex < 0 || propIndex > 255)
			throw new KNXIllegalArgumentException("argument value out of range");
		final byte[] send = DataUnitBuilder.createAPDU(PROPERTY_DESC_READ, new byte[] {
			(byte) objIndex, (byte) propertyId, (byte) (propertyId == 0 ? propIndex : 0) });

		for (int i = 0; i < 2; i++) {
			final byte[] apdu = sendWait(dst, priority, send, PROPERTY_DESC_RESPONSE, 7, 7);
			// make sure the response contains the requested description
			final boolean oiOk = objIndex == (apdu[2] & 0xff);
			final boolean pidOk = propertyId == 0 || propertyId == (apdu[3] & 0xff);
			final boolean pidxOk = propertyId != 0 || propIndex == (apdu[4] & 0xff);
			if (oiOk && pidOk && pidxOk) {
				// max_nr_elem field is a 4bit exponent + 12bit unsigned
				// on problem this field is 0
				if (apdu[6] == 0 && apdu[7] == 0)
					throw new KNXRemoteException("got no property description (object non-existant?)");
				return new byte[] { apdu[2], apdu[3], apdu[4], apdu[5], apdu[6], apdu[7], apdu[8] };
			}

			logger.log(WARNING, "wrong description response for OI {0} PID {1} prop idx {2} (got {3}|{4} (idx {5}))",
					objIndex, propertyId, propIndex, apdu[2] & 0xff, apdu[3] & 0xff, apdu[4] & 0xff);
		}
		throw new KNXTimeoutException("timeout occurred while waiting for data response");
	}

	@Override
	public byte[] callFunctionProperty(final Destination dst, final int objectType, final int objInstance,
			final int propertyId, final int serviceId, final byte... serviceInfo)
			throws KNXException, InterruptedException {
		return functionProperty(FunctionPropertyExtCommand, dst, objectType, objInstance, propertyId, serviceId,
				serviceInfo);
	}

	@Override
	public byte[] readFunctionPropertyState(final Destination dst, final int objectType, final int objInstance,
			final int propertyId, final int serviceId, final byte... serviceInfo)
			throws KNXException, InterruptedException {
		return functionProperty(FunctionPropertyExtStateRead, dst, objectType, objInstance, propertyId, serviceId,
				serviceInfo);
	}

	private byte[] functionProperty(final int cmd, final Destination dst, final int objectType, final int objInstance,
			final int propertyId, final int service, final byte... info)
			throws KNXLinkClosedException, KNXDisconnectException, KNXTimeoutException, KNXInvalidResponseException,
			KNXRemoteException, InterruptedException {

		if (objectType < 0 || objectType > 0xffff || objInstance < 0 || objInstance > 0xfff || propertyId < 0
				|| propertyId > 0xfff || service < 0 || service > 0xff)
			throw new KNXIllegalArgumentException("argument value out of range");

		final var asdu = ByteBuffer.allocate(7 + info.length).putShort((short) objectType)
				.put((byte) (objInstance >> 4)).put((byte) (((objInstance & 0xf) << 4) | (propertyId >> 8)))
				.put((byte) propertyId).put((byte) 0).put((byte) service).put(info);

		final long startSend = send(dst, priority, createAPDU(cmd, asdu.array()), FunctionPropertyExtStateResponse);
		final var responses = waitForResponses(FunctionPropertyExtStateResponse, 6, 252, startSend, responseTimeout,
				true, (source, apdu) -> {
					if (source.equals(dst.getAddress()))
						return extractFunctionPropertyExtData(objectType, objInstance, propertyId, apdu);
					return Optional.empty();
				});

		final byte[] response = responses.get(0);
		final var returnCode = ReturnCode.of(response[0] & 0xff);
		if (returnCode != ReturnCode.Success)
			throw new KNXRemoteException(format("function property response for %d(%d)|%d service %d: %s",
					objectType, objInstance, propertyId, service, returnCode.description()));
		return response;
	}

	private static Optional<byte[]> extractFunctionPropertyExtData(final int objectType, final int oinstance,
			final int propertyId, final byte[] apdu) {
		final int receivedIot = (apdu[2] & 0xff) << 8 | (apdu[3] & 0xff);
		final int receivedOinst = (apdu[4] & 0xff) << 4 | (apdu[5] & 0xf0) >> 4;
		final int receivedPid = (apdu[5] & 0x0f) << 8 | (apdu[6] & 0xff);
		return receivedIot == objectType && receivedOinst == oinstance && receivedPid == propertyId
				? Optional.of(Arrays.copyOfRange(apdu, 7, apdu.length)) : Optional.empty();
	}

	@Override
	public int readADC(final Destination dst, final int channel, final int repeat)
		throws KNXTimeoutException, KNXDisconnectException, KNXRemoteException,
		KNXLinkClosedException, InterruptedException
	{
		if (channel < 0 || channel > 63 || repeat < 0 || repeat > 255)
			throw new KNXIllegalArgumentException("ADC arguments out of range");
		if (!dst.isConnectionOriented())
			throw new KNXIllegalArgumentException("read ADC requires connection-oriented mode: " + dst);
		final byte[] apdu = sendWait(dst, priority,
				DataUnitBuilder.createLengthOptimizedAPDU(ADC_READ, new byte[] { (byte) channel,
					(byte) repeat }), ADC_RESPONSE, 3, 3);
		if (apdu[2] == 0)
			throw new KNXRemoteException("error reading value of A/D converter");
		return ((apdu[3] & 0xff) << 8) | apdu[4] & 0xff;
	}

	@Override
	public byte[] readMemory(final Destination dst, final int startAddr, final int bytes)
		throws KNXTimeoutException, KNXDisconnectException, KNXRemoteException,
		KNXLinkClosedException, InterruptedException
	{
		final int maxStartAddress = extMemoryServices ? 0xffffff : 0xffff;
		final int maxBytes = extMemoryServices ? 248 : 63;
		if (startAddr < 0 || startAddr > maxStartAddress || bytes < 1 || bytes > maxBytes)
			throw new KNXIllegalArgumentException("argument value out of range");
		if (!dst.isConnectionOriented())
			throw new KNXIllegalArgumentException("read memory requires connection-oriented mode: " + dst);

		// use extended read service for memory access above 65 K
		if (startAddr > 0xffff) {
			final byte[] send = createAPDU(MemoryExtendedRead,
					new byte[] { (byte) bytes, (byte) (startAddr >>> 16), (byte) (startAddr >>> 8), (byte) startAddr });
			final byte[] apdu = sendWait(dst, priority, send, MemoryExtendedReadResponse, 4, 252);
			final ReturnCode ret = ReturnCode.of(apdu[2] & 0xff);
			if (ret != ReturnCode.Success)
				throw new KNXRemoteException(
						format("read memory from %s 0x%x: %s", dst.getAddress(), startAddr, ret.description()));
			return Arrays.copyOfRange(apdu, 6, apdu.length);
		}

		final byte[] apdu = sendWait(dst, priority,
				createLengthOptimizedAPDU(MEMORY_READ,
						new byte[] { (byte) bytes, (byte) (startAddr >>> 8), (byte) startAddr }),
				MEMORY_RESPONSE, 2, 65);
		int no = apdu[1] & 0x3F;
		if (no == 0)
			throw new KNXRemoteException("could not read memory from 0x"
					+ Integer.toHexString(startAddr));
		final byte[] mem = new byte[no];
		while (--no >= 0)
			mem[no] = apdu[4 + no];
		return mem;
	}

	@Override
	public void writeMemory(final Destination dst, final int startAddr, final byte[] data)
		throws KNXDisconnectException, KNXTimeoutException, KNXRemoteException,
		KNXLinkClosedException, InterruptedException
	{
		final int maxStartAddress = extMemoryServices ? 0xffffff : 0xffff;
		final int maxBytes = extMemoryServices ? 250 : 63;
		if (startAddr < 0 || startAddr > maxStartAddress || data.length == 0 || data.length > maxBytes)
			throw new KNXIllegalArgumentException("argument value out of range");

		if (!dst.isConnectionOriented())
			throw new KNXIllegalArgumentException("write memory requires connection-oriented mode: " + dst);

		// use extended write service for memory access above 65 K
		if (startAddr > 0xffff) {
			final byte[] addrBytes = { (byte) (startAddr >>> 16), (byte) (startAddr >>> 8), (byte) startAddr };
			final byte[] asdu = allocate(4 + data.length).put((byte) data.length).put(addrBytes).put(data).array();
			final byte[] send = createAPDU(MemoryExtendedWrite, asdu);
			final byte[] apdu = sendWait(dst, priority, send, MemoryExtendedWriteResponse, 4, 252);
			final ReturnCode ret = ReturnCode.of(apdu[2] & 0xff);
			if (ret == ReturnCode.Success)
				return;
			String desc = ret.description();
			if (ret == ReturnCode.SuccessWithCrc) {
				final int crc = ((apdu[6] & 0xff) << 8) | (apdu[7] & 0xff);
				if (crc16Ccitt(asdu) == crc)
					return;
				desc = "data verification failed (crc mismatch)";
			}
			throw new KNXRemoteException(format("write memory to %s 0x%x: %s", dst.getAddress(), startAddr, desc));
		}

		final byte[] asdu = new byte[data.length + 3];
		asdu[0] = (byte) data.length;
		asdu[1] = (byte) (startAddr >> 8);
		asdu[2] = (byte) startAddr;
		for (int i = 0; i < data.length; ++i)
			asdu[3 + i] = data[i];
		final byte[] send = DataUnitBuilder.createLengthOptimizedAPDU(MEMORY_WRITE, asdu);
		if (dst.isVerifyMode()) {
			// explicitly read back data
			final byte[] apdu = sendWait(dst, priority, send, MEMORY_RESPONSE, 2, 65);
			if ((apdu[1] & 0x3f) == 0)
				throw new KNXRemoteException("remote app. could not write memory");
			if (apdu.length - 4 != data.length)
				throw new KNXInvalidResponseException("number of memory bytes differ");
			for (int i = 4; i < apdu.length; ++i)
				if (apdu[i] != asdu[i - 1])
					throw new KNXRemoteException("verify failed (erroneous memory data)");
		}
		else {
			send(dst, priority, send);
		}
	}

	static int crc16Ccitt(final byte[] input) {
		final int polynom = 0x1021;
		final byte[] padded = Arrays.copyOf(input, input.length + 2);
		int result = 0xffff;
		for (int i = 0; i < 8 * padded.length; i++) {
			result <<= 1;
			final int nextBit = (padded[i / 8] >> (7 - (i % 8))) & 0x1;
			result |= nextBit;
			if ((result & 0x10000) != 0)
				result ^= polynom;
		}
		return result & 0xffff;
	}

	@Override
	public int authorize(final Destination dst, final byte[] key)
		throws KNXDisconnectException, KNXTimeoutException, KNXRemoteException,
		KNXLinkClosedException, InterruptedException
	{
		if (key.length != 4)
			throw new KNXIllegalArgumentException("length of authorize key not 4 bytes");
		if (!dst.isConnectionOriented())
			throw new KNXIllegalArgumentException("authorize requires connection-oriented mode: " + dst);
		final byte[] asdu = new byte[] { 0, key[0], key[1], key[2], key[3] };
		final byte[] apdu = sendWait(dst, priority,
			DataUnitBuilder.createAPDU(AUTHORIZE_READ, asdu), AUTHORIZE_RESPONSE, 1, 1);
		final int level = apdu[2] & 0xff;
		if (level > 15)
			throw new KNXInvalidResponseException("authorization level out of range [0..15]");
		return level;
	}

	@Override
	public void writeKey(final Destination dst, final int level, final byte[] key)
		throws KNXTimeoutException, KNXDisconnectException, KNXRemoteException,
		KNXLinkClosedException, InterruptedException
	{
		// level 255 is free access
		if (level < 0 || level > 254 || key.length != 4)
			throw new KNXIllegalArgumentException("level out of range or key length not 4 bytes");
		if (!dst.isConnectionOriented())
			throw new KNXIllegalArgumentException("write key requires connection-oriented mode: " + dst);
		final byte[] apdu = sendWait(dst, priority,
			DataUnitBuilder.createAPDU(KEY_WRITE, new byte[] { (byte) level, key[0],
				key[1], key[2], key[3] }), KEY_RESPONSE, 1, 1);
		if ((apdu[1] & 0xFF) == 0xFF)
			throw new KNXRemoteException("access denied: current access level > write level");
	}

	@Override
	public boolean isOpen()
	{
		return !detached;
	}

	@Override
	public KNXNetworkLink detach()
	{
		tl.removeTransportListener(tlListener);
		final KNXNetworkLink lnk = detachTransportLayer ? tl.detach() : null;
		if (lnk != null) {
			logger.log(DEBUG, "detached from {0}", lnk);
		}
		listeners.removeAll();
		sal.close();
		detached = true;
		return lnk;
	}

	/**
	 * @return the transport layer instance used by this management client
	 */
	protected TransportLayer transportLayer() { return tl; }

	/**
	 * Sends the supplied {@code apdu} without registering any expected service response,
	 * optionally encrypting the data unit before sending.
	 *
	 * @param d transport layer destination
	 * @param p message priority
	 * @param apdu apdu
	 * @throws KNXTimeoutException
	 * @throws KNXDisconnectException
	 * @throws KNXLinkClosedException
	 * @throws InterruptedException
	 */
	protected void send(final Destination d, final Priority p, final byte[] apdu)
			throws KNXTimeoutException, KNXDisconnectException, KNXLinkClosedException, InterruptedException {
		send(d, p, apdu, 0, null);
	}

	/**
	 * Sends the supplied {@code apdu} and registers the expected service
	 * {@code response}, optionally encrypting the data unit before sending.
	 *
	 * @param d transport layer destination
	 * @param p message priority
	 * @param apdu apdu
	 * @param responseServiceType expected service response registered before send
	 * @return timestamp when service response was registered
	 * @throws KNXTimeoutException
	 * @throws KNXDisconnectException
	 * @throws KNXLinkClosedException
	 * @throws InterruptedException
	 */
	protected long send(final Destination d, final Priority p, final byte[] apdu, final int responseServiceType)
			throws KNXTimeoutException, KNXDisconnectException, KNXLinkClosedException, InterruptedException {
		return send(d, p, apdu, responseServiceType, null);
	}

	/**
	 * Waits for one or more service responses of type {@code responseServiceType} up to a specified {@code timeout}.
	 *
	 * @param responseServiceType response service type
	 * @param minAsduLen minimum accepted asdu length of a response
	 * @param maxAsduLen maximum accepted asdu length of a response
	 * @param start timestamp obtained by {@link #send(Destination, Priority, byte[], int)}
	 * @param timeout maximum time this method will wait for responses
	 * @param oneResponseOnly {@code true} if this method should return with the first valid response,
	 *        {@code false} to await the specified {@code timeout}
	 * @param responseFilter filter a response according to its content, the filter parameters are the response source address and apdu
	 * @return list of accepted responses
	 * @throws KNXInvalidResponseException
	 * @throws KNXTimeoutException
	 * @throws InterruptedException
	 */
	protected List<byte[]> waitForResponses(final int responseServiceType, final int minAsduLen, final int maxAsduLen,
			final long start, final Duration timeout, final boolean oneResponseOnly,
			final BiFunction<IndividualAddress, byte[], Optional<byte[]>> responseFilter)
					throws KNXInvalidResponseException, KNXTimeoutException, InterruptedException {

		long remaining = timeout.toMillis();
		final long end = start / 1_000_000L + remaining;
		final var responses = new ArrayList<byte[]>();
		synchronized (indications) {
			while (remaining > 0) {
				for (final Iterator<FrameEvent> i = indications.iterator(); i.hasNext();) {
					final var event = i.next();
					// purge outdated events
					if (start > event.id() + responseTimeout.toNanos()) {
						i.remove();
						continue;
					}
					// causality
					if (start > event.id())
						continue;
					final CEMI frame = event.getFrame();
					final byte[] apdu = frame.getPayload();
					if (responseServiceType != DataUnitBuilder.getAPDUService(apdu))
						continue;

					final IndividualAddress source = frame instanceof CEMILData ? ((CEMILData) frame).getSource() : new IndividualAddress(0);
					if (apdu.length < minAsduLen + 2 || apdu.length > maxAsduLen + 2) {
						final String s = "invalid ASDU response length " + (apdu.length - 2) + " bytes, expected "
								+ minAsduLen + " to " + maxAsduLen;
						logger.log(WARNING, "received response from " + source + " with " + s);
						if (oneResponseOnly)
							throw new KNXInvalidResponseException(s);
					}
					responseFilter.apply(source, apdu).ifPresent(response -> {
						responses.add(response);
						i.remove();
					});
					if (!responses.isEmpty() && oneResponseOnly)
						return responses;
				}
				indications.wait(remaining);
				remaining = end - System.nanoTime() / 1_000_000L;
			}
		}
		if (responses.isEmpty())
			throw new KNXTimeoutException("timeout waiting for data response");
		return responses;
	}

	/**
	 * Sends the supplied {@code apdu} using the assigned transport layer, optionally encrypting the data unit before
	 * sending, and waits up to a specified {@code timeout} for a single response of service type {@code responseServiceType}.
	 *
	 * @param d transport layer destination
	 * @param p message priority
	 * @param apdu apdu
	 * @param responseServiceType expected service response
	 * @param minAsduLen minimum accepted asdu length of response
	 * @param maxAsduLen maximum accepted asdu length of response
	 * @param timeout maximum time this method will wait for a response
	 * @return the response apdu
	 * @throws KNXDisconnectException
	 * @throws KNXTimeoutException
	 * @throws KNXInvalidResponseException
	 * @throws KNXLinkClosedException
	 * @throws InterruptedException
	 */
	protected byte[] sendWait(final Destination d, final Priority p, final byte[] apdu, final int responseServiceType,
			final int minAsduLen, final int maxAsduLen, final Duration timeout) throws KNXDisconnectException,
			KNXTimeoutException, KNXInvalidResponseException, KNXLinkClosedException, InterruptedException {
		final long start = send(d, p, apdu, responseServiceType);
		return waitForResponse(d.getAddress(), responseServiceType, minAsduLen, maxAsduLen, start, timeout);
	}

	private int maxApduLength(final Destination dst) throws KNXLinkClosedException, InterruptedException {
		final Optional<Integer> max = dst.maxApduLength();
		if (max.isPresent())
			return max.get();

		final var link = ((TransportLayerImpl) tl).link();
		final int maxLinkApdu = link.getKNXMedium().maxApduLength();

		int maxDeviceApdu = 15;
		// always set a default to avoid multiple queries
		dst.maxApduLength(maxDeviceApdu);
		if (maxLinkApdu > maxDeviceApdu) {
			try {
				// note, this read property call already requires a default minimum apdu to be set
				final var data = readProperty(dst, 0, PID.MAX_APDULENGTH, 1, 1);
				maxDeviceApdu = (data[0] & 0xff) << 8 | data[1] & 0xff;
				dst.maxApduLength(Math.min(maxLinkApdu, maxDeviceApdu));
			}
			catch (KNXTimeoutException | KNXRemoteException | KNXDisconnectException e) {
				logger.log(DEBUG, "use max. APDU length of 15 bytes for {0}", dst.getAddress());
			}
		}
		return dst.maxApduLength().get();
	}

	private int maxAsduLength(final Destination dst) throws KNXLinkClosedException, InterruptedException {
		return maxApduLength(dst) - 1;
	}

	private long registerActiveService(final int serviceType) {
		final long now = System.nanoTime();
		activeServiceResponses.merge(serviceType, now + responseTimeout.toNanos(),
				(oldValue, value) -> oldValue < value ? value : oldValue);
		return now;
	}

	private boolean isActiveService(final int serviceType, final long timestamp) {
		return activeServiceResponses.computeIfPresent(serviceType,
				(__, activeUntil) -> activeUntil < timestamp ? null : activeUntil) != null;
	}

	private boolean isActiveService(final FrameEvent e) {
		return isActiveService(DataUnitBuilder.getAPDUService(e.getFrame().getPayload()), e.id());
	}

	private long send(final Destination d, final Priority p, final byte[] apdu, final int response,
			final byte[] updateToolKey) throws KNXTimeoutException, KNXDisconnectException, KNXLinkClosedException,
			InterruptedException {
		final long start = response != 0 ? registerActiveService(response) : 0;
		final var secCtrl = SecurityControl.of(DataSecurity.AuthConf, toolAccess);
		final var sapdu = sal.secureData(src, d.getAddress(), apdu, secCtrl).orElse(apdu);

		if (updateToolKey != null) {
			sal.security().deviceToolKeys().put(d.getAddress(), updateToolKey);
			logger.log(INFO, "update device toolkey for {0}", d.getAddress());
		}

		if (d.isConnectionOriented())
			tl.sendData(d, p, sapdu);
		else
			tl.sendData(d.getAddress(), p, sapdu);
		return start;
	}

	private byte[] sendWait(final Destination d, final Priority p, final byte[] apdu, final int response,
			final int minAsduLen, final int maxAsduLen) throws KNXDisconnectException, KNXTimeoutException,
			KNXInvalidResponseException, KNXLinkClosedException, InterruptedException {
		return sendWait(d, p, apdu, response, minAsduLen, maxAsduLen, responseTimeout);
	}

	// min + max ASDU len are *not* including any field that contains ACPI
	private byte[] waitForResponse(final IndividualAddress from, final int serviceType, final int minAsduLen,
		final int maxAsduLen, final long start, final Duration timeout)
				throws KNXInvalidResponseException, KNXTimeoutException, InterruptedException {
		return waitForResponses(serviceType, minAsduLen, maxAsduLen, start, timeout, true,
				(source, apdu) -> source.equals(from) ? Optional.of(apdu) : Optional.empty()).get(0);
	}

	private List<byte[]> readBroadcast(final Priority p, final byte[] apdu,
		final int response, final int minAsduLen, final int maxAsduLen, final boolean oneOnly)
		throws KNXLinkClosedException, KNXInvalidResponseException, KNXTimeoutException,
		InterruptedException
	{
		final long start = registerActiveService(response);
		tl.broadcast(true, p, apdu);
		return waitForResponses(response, minAsduLen, maxAsduLen, start, responseTimeout, oneOnly,
				(source, apdu1) -> Optional.of(apdu1));
	}

	// cut domain addresses out of APDUs
	private static List<byte[]> makeDOAs(final List<byte[]> l)
	{
		for (int i = 0; i < l.size(); ++i) {
			final byte[] pdu = l.get(i);
			l.set(i, Arrays.copyOfRange(pdu, 2, pdu.length));
		}
		return l;
	}

	// returns property read.res element values
	private static byte[] extractPropertyElements(final byte[] apdu, final int objIndex, final int propertyId,
		final int elements) throws KNXRemoteException
	{
		final int oi = apdu[2] & 0xff;
		final int pid = apdu[3] & 0xff;
		if (oi != objIndex || pid != propertyId)
			throw new KNXInvalidResponseException(
					String.format("property response mismatch, expected OI %d PID %d (received %d|%d)", objIndex,
							propertyId, oi, pid));
		// check if number of elements is 0, indicates access problem
		final int number = (apdu[4] & 0xFF) >>> 4;
		if (number == 0)
			throw new KNXRemoteException("property access OI " + oi + " PID " + pid + " failed/forbidden");
		if (number != elements)
			throw new KNXInvalidResponseException(String.format(
					"property access OI %d PID %d expected %d elements (received %d)", oi, pid, elements, number));
		final byte[] prop = new byte[apdu.length - 6];
		for (int i = 0; i < prop.length; ++i)
			prop[i] = apdu[i + 6];
		return prop;
	}
}
