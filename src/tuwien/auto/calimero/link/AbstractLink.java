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

package tuwien.auto.calimero.link;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.lang.System.Logger;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.StringJoiner;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.cemi.AdditionalInfo;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.cemi.CEMILDataEx;
import tuwien.auto.calimero.cemi.CemiTData;
import tuwien.auto.calimero.cemi.RFMediumInfo;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.link.medium.RFSettings;
import tuwien.auto.calimero.link.medium.TPSettings;
import tuwien.auto.calimero.log.LogService;

/**
 * Provides an abstract KNX network link implementation, independent of the actual communication
 * protocol and medium access. The link supports EMI1/EMI2/cEMI format. Subtypes extend this link by
 * specifying the protocol, e.g., KNXnet/IP, or providing a specific implementation of medium
 * access, e.g., via a serial port driver. In most cases, it is sufficient for a subtype to provide
 * an implementation of {@link #onSend(CEMILData, boolean)} or
 * {@link #onSend(KNXAddress, byte[], boolean)}, as well as {@link #onClose()}. If the communication
 * protocol message format differs from the supported EMI 1/2 or cEMI, a subtype needs to override
 * {@link #onReceive(FrameEvent)}. For receiving and dispatching frames from the specified protocol,
 * a subtype uses the KNXListener {@link AbstractLink#notifier} as connection listener.
 * <p>
 * In general, once a link has been closed, it is not available for further link communication and
 * cannot be reopened. For many use cases, a {@link Connector} is useful for creating KNX network
 * links.
 *
 * @author B. Malinowsky
 * @see KNXNetworkLinkIP
 * @see KNXNetworkLinkFT12
 * @see KNXNetworkLinkUsb
 * @see KNXNetworkLinkTpuart
 * @see Connector
 */
public abstract class AbstractLink<T extends AutoCloseable> implements KNXNetworkLink
{
	/** Logger for this link instance. */
	protected final Logger logger;

	/**
	 * Listener and notifier of KNX link events, add as connection listener to the underlying
	 * protocol during initialization.
	 */
	protected final EventNotifier<NetworkLinkListener> notifier;
	volatile boolean wrappedByConnector;

	/** The message format to generate: cEMI or EMI1/EMI2. */
	protected boolean cEMI = true;

	/**
	 * With cEMI format, use {@link #onSend(KNXAddress, byte[], boolean)} if set {@code true},
	 * use {@link #onSend(CEMILData, boolean)} if set {@code false}.
	 */
	protected boolean sendCEmiAsByteArray;

	private final String name;
	private volatile boolean closed;
	private volatile int hopCount = 6;
	private KNXMediumSettings medium;

	final T conn;

	private CEMIDevMgmt devMgmt;


	private static final MethodHandle baosServiceFactory_MH;
	static {
		MethodHandle mh = null;
		try {
			final var clazz = Class.forName("tuwien.auto.calimero.baos.BaosService");
			final var lookup = MethodHandles.lookup();
			final var baosModeType = MethodType.methodType(clazz, ByteBuffer.class);
			mh = lookup.findStatic(clazz, "from", baosModeType);
		}
		catch (ClassNotFoundException | IllegalAccessException | NoSuchMethodException e) {}
		baosServiceFactory_MH = mh;
	}

	private final class LinkNotifier extends EventNotifier<NetworkLinkListener>
	{
		private static final int PeiIdentifyCon = 0xa8;
		private static final int BaosMainService = 0xf0;

		LinkNotifier() {
			super(AbstractLink.this, AbstractLink.this.logger);
		}

		@Override
		public void frameReceived(final FrameEvent e)
		{
			try {
				final byte[] frame = e.getFrameBytes();
				if (frame != null) {
					// with EMI1 frames, there is the possibility we receive some left-over Get-Value responses
					// from BCU switching during link setup, silently discard them
					if (BcuSwitcher.isEmi1GetValue(frame[0] & 0xff))
						return;

					if ((frame[0] & 0xff) == PeiIdentifyCon) {
						logger.log(INFO, "PEI identify {0}", DataUnitBuilder.toHex(frame, " "));
						final int manufacturer = unsigned(frame[3], frame[4]);
						if (manufacturer == 0xc5) {
							logger.log(INFO, "link connected to weinzierl device");
						}
					}

					// intercept BAOS services (ObjectServer protocol), necessary because BaosLinkAdapter has no direct
					// access to frame receive events
					if (baosServiceFactory_MH != null && (frame[0] & 0xff) == BaosMainService) {
						try {
							final var baosEvent = baosServiceFactory_MH.invoke(ByteBuffer.wrap(frame));
							dispatchCustomEvent(baosEvent);
						}
						catch (KNXFormatException | RuntimeException ex) {
							throw ex;
						}
						catch (final Throwable t) {
							t.printStackTrace();
						}
						return;
					}
				}

				final CEMI cemi = onReceive(e);
				if (cemi instanceof CEMIDevMgmt)
					onDevMgmt((CEMIDevMgmt) cemi);
				else if (cemi instanceof CemiTData) {
					final var tdata = (CemiTData) cemi;
					final int mc = tdata.getMessageCode();
					if (mc == CemiTData.IndividualIndication || mc == CemiTData.ConnectedIndication) {
						addEvent(l -> l.indication(new FrameEvent(source, tdata)));
						logger.log(DEBUG, "received {0}", tdata);
					}
					else
						logger.log(WARNING, "unsupported cEMI T-Data, msg code = 0x{0}: {1}", Integer.toHexString(mc), tdata);
				}

				// from this point on, we are only dealing with L_Data
				if (!(cemi instanceof CEMILData))
					return;
				final CEMILData ldata = (CEMILData) cemi;
				final int mc = cemi.getMessageCode();
				if (mc == CEMILData.MC_LDATA_IND) {
					addEvent(l -> l.indication(new FrameEvent(source, ldata)));
					logger.log(DEBUG, "indication {0}", ldata);
				}
				else if (mc == CEMILData.MC_LDATA_CON) {
					addEvent(l -> l.confirmation(new FrameEvent(source, ldata)));
					if (ldata.isPositiveConfirmation())
						logger.log(DEBUG, "confirmation of {0}", ldata.getDestination());
					else
						logger.log(WARNING, "negative confirmation of {0}: {1}", ldata.getDestination(),
								DataUnitBuilder.toHex(ldata.toByteArray(), " "));
				}
				else
					logger.log(WARNING, "unspecified L-data frame event - ignored, msg code = 0x" + Integer.toHexString(mc));
			}
			catch (final KNXFormatException | RuntimeException ex) {
				logger.log(WARNING, "received unspecified frame {0}", DataUnitBuilder.toHex(e.getFrameBytes(), " "), ex);
			}
		}

		@Override
		public void connectionClosed(final CloseEvent e)
		{
			AbstractLink.this.closed = true;
			logger.log(DEBUG, "link closed");
			if (wrappedByConnector) {
				getListeners().listeners().stream().filter(Connector.Link.class::isInstance)
					.forEach(l -> l.linkClosed(e));
				return;
			}
			super.connectionClosed(e);
		}
	};

	/**
	 * @param connection if not {@code null}, the link object will close this resource as last
	 *        action before returning from {@link #close()}, relinquishing any underlying resources
	 * @param name the link name
	 * @param settings medium settings of the accessed KNX network
	 */
	protected AbstractLink(final T connection, final String name, final KNXMediumSettings settings)
	{
		conn = connection;
		this.name = name;
		logger = LogService.getLogger("calimero.link." + getName());
		notifier = new LinkNotifier();
		setKNXMedium(settings);
		notifier.start();
	}

	/**
	 * This constructor does not start the event notifier.
	 *
	 * @param name the link name
	 * @param settings medium settings of the accessed KNX network
	 */
	protected AbstractLink(final String name, final KNXMediumSettings settings)
	{
		conn = null;
		this.name = name;
		logger = LogService.getLogger("calimero.link." + getName());
		notifier = new LinkNotifier();
		setKNXMedium(settings);
	}

	@Override
	public final synchronized void setKNXMedium(final KNXMediumSettings settings)
	{
		if (settings == null)
			throw new KNXIllegalArgumentException("medium settings are mandatory");
		if (medium != null && !settings.getClass().isAssignableFrom(medium.getClass())
				&& !medium.getClass().isAssignableFrom(settings.getClass()))
			throw new KNXIllegalArgumentException("medium differs");
		medium = settings;
	}

	@Override
	public final synchronized KNXMediumSettings getKNXMedium()
	{
		return medium;
	}

	@Override
	public void addLinkListener(final NetworkLinkListener l)
	{
		notifier.addListener(l);
	}

	@Override
	public void removeLinkListener(final NetworkLinkListener l)
	{
		notifier.removeListener(l);
	}

	@Override
	public final void setHopCount(final int count)
	{
		if (count < 0 || count > 7)
			throw new KNXIllegalArgumentException("hop count out of range [0..7]");
		hopCount = count;
		logger.log(DEBUG, "hop count set to {0}", count);
	}

	@Override
	public final int getHopCount()
	{
		return hopCount;
	}

	@Override
	public void sendRequest(final KNXAddress dst, final Priority p, final byte[] nsdu)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		send(CEMILData.MC_LDATA_REQ, dst, p, nsdu, false);
	}

	@Override
	public void sendRequestWait(final KNXAddress dst, final Priority p, final byte[] nsdu)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		send(CEMILData.MC_LDATA_REQ, dst, p, nsdu, true);
	}

	@Override
	public void send(final CEMILData msg, final boolean waitForCon)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		if (closed)
			throw new KNXLinkClosedException("link closed");
		if (cEMI && !sendCEmiAsByteArray) {
			final CEMILData adjusted = adjustMsgType(msg);
			addMediumInfo(adjusted);
			onSend(adjusted, waitForCon);
			return;
		}
		onSend(msg.getDestination(), createEmi(msg, waitForCon), waitForCon);
	}

	@Override
	public final String getName()
	{
		return name;
	}

	@Override
	public final boolean isOpen()
	{
		return !closed;
	}

	@Override
	public final void close()
	{
		synchronized (this) {
			if (closed)
				return;
			closed = true;
		}
		onClose();
		try {
			if (conn != null)
				conn.close();
		}
		catch (final Exception ignore) {}
		notifier.quit();
	}

	@Override
	public String toString()
	{
		return "link" + (closed ? " (closed) " : " ") + getName() + " " + medium + ", hopcount " + hopCount;
	}

	/**
	 * Prepares the message in the required EMI format, using the supplied message parameters, and
	 * calls {@link #onSend(CEMILData, boolean)} and {@link #onSend(KNXAddress, byte[], boolean)}.
	 *
	 * @param mc message code
	 * @param dst KNX destination address
	 * @param p message priority
	 * @param nsdu NSDU
	 * @param waitForCon {@code true} to wait for a link layer confirmation response,
	 *        {@code false} to not wait for the confirmation
	 * @throws KNXTimeoutException on a timeout during send or while waiting for the confirmation
	 * @throws KNXLinkClosedException if the link is closed
	 */
	protected void send(final int mc, final KNXAddress dst, final Priority p, final byte[] nsdu,
		final boolean waitForCon) throws KNXTimeoutException, KNXLinkClosedException
	{
		if (closed)
			throw new KNXLinkClosedException("link closed");
		if (cEMI && !sendCEmiAsByteArray) {
			final CEMI f = cEMI(mc, dst, p, nsdu);
			if (f instanceof CEMILData)
				onSend((CEMILData) f, waitForCon);
			else if (f instanceof CemiTData)
				onSend((CemiTData) f);
			return;
		}
		onSend(dst, createEmi(mc, dst, p, nsdu), waitForCon);
	}

	/**
	 * Implement with the connection/medium-specific protocol send primitive. Sends the message
	 * supplied as byte array over the link. In case a L-Data confirmation is requested, the message
	 * send is only successful if the corresponding confirmation is received.
	 *
	 * @param dst for logging purposes only: the KNX destination address, or {@code null}
	 * @param msg the message to send
	 * @param waitForCon {@code true} to wait for a link layer confirmation response,
	 *        {@code false} to not wait for the confirmation
	 * @throws KNXTimeoutException on a timeout during send or while waiting for the confirmation
	 * @throws KNXLinkClosedException if the link is closed
	 */
	protected abstract void onSend(KNXAddress dst, byte[] msg, boolean waitForCon)
		throws KNXTimeoutException, KNXLinkClosedException;

	/**
	 * Implement with the connection/medium-specific protocol send primitive. Sends the message
	 * supplied in cEMI L-Data format over the link. In case a L-Data confirmation is requested, the
	 * message send is only successful if the corresponding confirmation is received.
	 *
	 * @param msg the message to send
	 * @param waitForCon {@code true}, if the communication protocol should block and wait for
	 *        the link layer confirmation (L-Data.con), executing all required retransmission
	 *        attempts and timeout validations, {@code false} if no confirmation is requested
	 * @throws KNXTimeoutException on a timeout during send or while waiting for the confirmation
	 * @throws KNXLinkClosedException if the link is closed
	 */
	protected abstract void onSend(CEMILData msg, boolean waitForCon)
		throws KNXTimeoutException, KNXLinkClosedException;

	/**
	 * Implement with the connection/medium-specific protocol send primitive for sending a message
	 * in cEMI T-Data format over the link.
	 *
	 * @param msg the message to send
	 * @throws KNXTimeoutException on a timeout during send
	 * @throws KNXLinkClosedException if the link is closed
	 */
	@SuppressWarnings("unused")
	protected void onSend(final CemiTData msg) throws KNXTimeoutException, KNXLinkClosedException {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns a cEMI representation, e.g., cEMI L-Data, using the received frame event for EMI and
	 * cEMI formats. Override this method if the used message format does not conform to the
	 * supported EMI 1/2 or cEMI format.
	 *
	 * @param e the received frame event
	 * @return the constructed cEMI message, e.g., cEMI L-Data
	 * @throws KNXFormatException on unsupported frame formats, or errors in the frame format
	 */
	protected CEMI onReceive(final FrameEvent e) throws KNXFormatException
	{
		final CEMI cemi = e.getFrame();
		if (cemi != null)
			return cemi;
		final byte[] frameBytes = e.getFrameBytes();
		return cEMI ? CEMIFactory.create(frameBytes,  0, frameBytes.length) : CEMIFactory.fromEmi(frameBytes);
	}

	/**
	 * Invoked on {@link #close()} to execute additional close sequences of the communication
	 * protocol, or releasing link-specific resources.
	 */
	protected void onClose() {}

	@SuppressWarnings("unused")
	void onSend(final CEMIDevMgmt frame) throws KNXException, InterruptedException {}

	void onDevMgmt(final CEMIDevMgmt f) {
		final int mc = f.getMessageCode();
		if (mc == CEMIDevMgmt.MC_PROPWRITE_CON) {
			if (f.isNegativeResponse())
				logger.log(ERROR, "L-DM negative response, " + f.getErrorMessage());
		}
		synchronized (this) {
			devMgmt = f;
			notifyAll();
		}
	}

	static final int cemiServerObject = 8;

	void mediumType() throws KNXException, InterruptedException {
		final int pidMediumType = 51;
		final int supplied = getKNXMedium().getMedium();
		final int types = read(cemiServerObject, pidMediumType).map(AbstractLink::unsigned).orElse(supplied);
		if ((types & supplied) != supplied)
			logger.log(WARNING, "wrong communication medium setting: using {0} to access {1} medium",
					KNXMediumSettings.getMediumString(supplied), mediumTypes(types));
	}

	private static String mediumTypes(final int types) {
		final var joiner = new StringJoiner(", ").setEmptyValue("unknown");
		if ((types & 0x02) > 0)
			joiner.add("TP1");
		if ((types & 0x04) > 0)
			joiner.add("PL110");
		if ((types & 0x10) > 0)
			joiner.add("RF");
		if ((types & 0x20) > 0)
			joiner.add("IP");
		return joiner.toString();
	}

	void setMaxApduLength() throws KNXException, InterruptedException {
		final KNXMediumSettings settings = getKNXMedium();
		maxApduLength().ifPresent(settings::setMaxApduLength);
		if (settings.maxApduLength() != 15)
			logger.log(DEBUG, "using max. APDU length of {0}", settings.maxApduLength());
	}

	Optional<Integer> maxApduLength() throws KNXException, InterruptedException {
		final int pidMaxApduLength = 56;
		return read(0, pidMaxApduLength).map(AbstractLink::unsigned);
	}

	volatile boolean baosMode;

	void baosMode(final boolean enable) throws KNXException, InterruptedException {
		final IndividualAddress dst = KNXMediumSettings.BackboneRouter;
		if (cEMI) {
			final int pidBaosSupport = 201;
			final var check = new CEMIDevMgmt(CEMIDevMgmt.MC_PROPREAD_REQ, cemiServerObject, 1, pidBaosSupport, 1, 1);
			onSend(check);
			final boolean supported = responseFor(CEMIDevMgmt.MC_PROPREAD_CON, pidBaosSupport).isPresent();
			if (!supported)
				throw new KNXException("device does not support BAOS mode");

			final var frame = BcuSwitcher.cemiCommModeRequest(enable ? BcuSwitcher.BaosMode : BcuSwitcher.DataLinkLayer);
			onSend(frame);
			responseFor(CEMIDevMgmt.MC_PROPWRITE_CON, BcuSwitcher.pidCommMode);

			final var recheck = new CEMIDevMgmt(CEMIDevMgmt.MC_PROPREAD_REQ, cemiServerObject, 1,
					BcuSwitcher.pidCommMode, 1, 1);
			onSend(recheck);
			responseFor(CEMIDevMgmt.MC_PROPREAD_CON, BcuSwitcher.pidCommMode)
					.ifPresent(mode -> logger.log(DEBUG, "comm mode {0}",
							(mode[0] & 0xff) == 0xf0 ? "BAOS" : DataUnitBuilder.toHex(mode, "")));
			baosMode = enable;
		}
		// ??? check baos support ahead
//		else if (activeEmi == EmiType.Emi1) {
			// NYI EMI1
//		}
		else {
			// NYI EMI2
			final int peiIdentifyReq = 0xa7;
//			final int PeiIdentifyCon = 0xa8;
			onSend(dst, new byte[] { (byte) peiIdentifyReq }, true);
		}
	}

	Optional<byte[]> read(final int objectType, final int pid) throws KNXException, InterruptedException {
		if (!cEMI)
			return Optional.empty();
		final int objectInstance = 1;
		onSend(new CEMIDevMgmt(CEMIDevMgmt.MC_PROPREAD_REQ, objectType, objectInstance, pid, 1, 1));
		return responseFor(CEMIDevMgmt.MC_PROPREAD_CON, pid);
	}

	// usable for max 31 data bits
	static int unsigned(final byte... data) {
		int value = 0;
		for (final byte b : data)
			value = (value << 8) | (b & 0xff);
		return value;
	}

	synchronized Optional<byte[]> responseFor(final int messageCode, final int pid) throws InterruptedException {
		long remaining = 1000L;
		final long end = System.nanoTime() / 1000_000 + remaining;

		while (remaining > 0) {
			if (devMgmt != null) {
				final CEMIDevMgmt f = devMgmt;
				devMgmt = null;

				if (f.getMessageCode() == messageCode && f.getPID() == pid) {
					final byte[] data = f.getPayload();
					if (f.isNegativeResponse() || data.length == 0)
						break;

					return Optional.of(data);
				}
			}
			wait(remaining);
			remaining = end - System.nanoTime() / 1000_000;
		}
		return Optional.empty();
	}

	private CEMILData adjustMsgType(final CEMILData msg)
	{
		final boolean srcOk = msg.getSource().getRawAddress() != 0;
		// just return if we don't need to adjust source address and don't need LDataEx
		if ((srcOk || medium.getDeviceAddress().getRawAddress() == 0)
				&& (medium instanceof TPSettings || msg instanceof CEMILDataEx))
			return msg;
		return CEMIFactory.create(srcOk ? null : medium.getDeviceAddress(), null, msg, true);
	}

	private void addMediumInfo(final CEMILData msg)
	{
		String s = "";
		if (medium instanceof PLSettings) {
			final CEMILDataEx f = (CEMILDataEx) msg;
			if (f.getAdditionalInfo(AdditionalInfo.PlMedium) != null)
				return;
			f.additionalInfo().add(AdditionalInfo.of(AdditionalInfo.PlMedium, ((PLSettings) medium).getDomainAddress()));
		}
		else if (medium.getMedium() == KNXMediumSettings.MEDIUM_RF) {
			final CEMILDataEx f = (CEMILDataEx) msg;
			if (f.getAdditionalInfo(AdditionalInfo.RfMedium) != null)
				return;
			final RFSettings rf = (RFSettings) medium;
			final byte[] sn = f.isDomainBroadcast() ? rf.getDomainAddress() : rf.serialNumber().array();
			f.additionalInfo().add(new RFMediumInfo(true, rf.isUnidirectional(), sn, 255, f.isSystemBroadcast()));
			s = f.isDomainBroadcast() ? " (using domain address)" : " (using device SN)";
		}
		else
			return;
		logger.log(TRACE, "add cEMI additional info for {0}{1}", medium.getMediumString(), s);
	}

	private void addMediumInfo(final CemiTData msg) {
		String s = "";
		if (medium instanceof PLSettings) {
			if (msg.additionalInfo().stream().anyMatch(info -> info.type() == AdditionalInfo.PlMedium))
				return;
			msg.additionalInfo().add(AdditionalInfo.of(AdditionalInfo.PlMedium, ((PLSettings) medium).getDomainAddress()));
		}
		else if (medium.getMedium() == KNXMediumSettings.MEDIUM_RF) {
			if (msg.additionalInfo().stream().anyMatch(info -> info.type() == AdditionalInfo.RfMedium))
				return;
			final RFSettings rf = (RFSettings) medium;
			msg.additionalInfo().add(new RFMediumInfo(true, rf.isUnidirectional(), rf.getDomainAddress(), 255, false));
			s = " (using domain address)";
		}
		else
			return;
		logger.log(TRACE, "add cEMI additional info for {0}{1}", medium.getMediumString(), s);
	}

	// Creates the target EMI format using L-Data message parameters
	private byte[] createEmi(final int mc, final KNXAddress dst, final Priority p, final byte[] nsdu)
	{
		if (cEMI)
			return cEMI(mc, dst, p, nsdu).toByteArray();

		final boolean repeat = true;
		final boolean ackRequest = false;
		final boolean posCon = true;
		return CEMIFactory.toEmi(mc, dst, p, repeat, ackRequest, posCon, hopCount, nsdu);
	}

	// Creates the target EMI format using a cEMI L-Data message
	private byte[] createEmi(final CEMILData f, final boolean waitForCon)
	{
		if (cEMI) {
			final CEMILData adjusted = adjustMsgType(f);
			addMediumInfo(adjusted);
			logger.log(DEBUG, "send {0}{1}", (waitForCon ? "(wait for confirmation) " : ""), adjusted);
			return adjusted.toByteArray();
		}
		return CEMIFactory.toEmi(f);
	}

	private CEMI cEMI(final int mc, final KNXAddress dst, final Priority p, final byte[] nsdu)
	{
		if (mc == CemiTData.IndividualRequest || mc == CemiTData.ConnectedRequest) {
			final var tdata = new CemiTData(mc, nsdu);
			addMediumInfo(tdata);
			return tdata;
		}

		final IndividualAddress src = medium.getDeviceAddress();
		// use default address 0 in system broadcast
		final KNXAddress d = dst == null ? GroupAddress.Broadcast : dst;
		final boolean repeat = mc != CEMILData.MC_LDATA_IND;
		final boolean tp = medium.getMedium() == KNXMediumSettings.MEDIUM_TP1;
		if (nsdu.length <= 16 && tp)
			return new CEMILData(mc, src, d, nsdu, p, repeat, hopCount);

		final CEMILDataEx f = new CEMILDataEx(mc, src, d, nsdu, p, repeat, domainBcast(dst), false, hopCount);
		addMediumInfo(f);
		return f;
	}

	private boolean domainBcast(final KNXAddress dst) {
		if (medium.getMedium() == KNXMediumSettings.MEDIUM_TP1)
			return true;
		if (medium.getMedium() == KNXMediumSettings.MEDIUM_PL110)
			return dst != null;
		if (medium.getMedium() == KNXMediumSettings.MEDIUM_RF) {
			final RFSettings rfSettings = (RFSettings) medium;
			if (rfSettings.isUnidirectional())
				return false;
			if (dst instanceof IndividualAddress)
				return true;
			return false; // we send broadcasts always as system broadcast
		}
		return true;
	}

	void dispatchCustomEvent(final Object event) {
		notifier.dispatchCustomEvent(event);
	}
}
