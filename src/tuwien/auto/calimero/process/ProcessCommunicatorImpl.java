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

package tuwien.auto.calimero.process;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.lang.System.Logger;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DetachEvent;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXInvalidResponseException;
import tuwien.auto.calimero.KNXRemoteException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.ReturnCode;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.dptxlator.DPT;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.dptxlator.DPTXlator2ByteFloat;
import tuwien.auto.calimero.dptxlator.DPTXlator3BitControlled;
import tuwien.auto.calimero.dptxlator.DPTXlator4ByteFloat;
import tuwien.auto.calimero.dptxlator.DPTXlator8BitUnsigned;
import tuwien.auto.calimero.dptxlator.DPTXlatorBoolean;
import tuwien.auto.calimero.dptxlator.DPTXlatorString;
import tuwien.auto.calimero.dptxlator.TranslatorTypes;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.secure.SecureApplicationLayer;
import tuwien.auto.calimero.secure.Security;

/**
 * This implementation of the process communicator uses in any case the DPT translators
 * {@link DPTXlatorBoolean}, {@link DPTXlator3BitControlled}, {@link DPTXlator8BitUnsigned},
 * {@link DPTXlator2ByteFloat}, {@link DPTXlator4ByteFloat}, {@link DPTXlatorString}. Other
 * translator types are loaded through {@link TranslatorTypes}.
 *
 * @author B. Malinowsky
 */
public class ProcessCommunicatorImpl implements ProcessCommunicator
{
	private final class NLListener implements NetworkLinkListener
	{
		@Override
		public void indication(final FrameEvent e)
		{
			final CEMILData f = (CEMILData) e.getFrame();
			final var apdu = f.getPayload();
			// can't be a process communication indication if too short
			if (apdu.length < 2)
				return;
			try {
				final int svc = DataUnitBuilder.getAPDUService(apdu);
				// Note: even if this is a read response we have waited for,
				// we nevertheless notify the listeners about it (we do *not* discard it)
				if (svc == GROUP_RESPONSE) {
					synchronized (indications) {
						if (indications.replace((GroupAddress) f.getDestination(), e) != null)
							indications.notifyAll();
					}
				}
				// notify listeners
				if (svc == GROUP_READ)
					fireGroupReadWrite(f, new byte[0], svc, false);
				else if (svc == GROUP_RESPONSE || svc == GROUP_WRITE)
					fireGroupReadWrite(f, DataUnitBuilder.extractASDU(apdu), svc, apdu.length <= 2);
			}
			catch (final RuntimeException rte) {
				logger.log(ERROR, "on group indication from {0}", f.getSource(), rte);
			}
		}

		private void fireGroupReadWrite(final CEMILData f, final byte[] asdu, final int svc, final boolean optimized)
		{
			final ProcessEvent e = new ProcessEvent(ProcessCommunicatorImpl.this, f.getSource(),
					(GroupAddress) f.getDestination(), svc, asdu, optimized);
			final Consumer<? super ProcessListener> c;
			if (svc == GROUP_READ)
				c = l -> l.groupReadRequest(e);
			else if (svc == GROUP_RESPONSE)
				c = l -> l.groupReadResponse(e);
			else
				c = l -> l.groupWrite(e);
			listeners.fire(c);
		}

		@Override
		public void linkClosed(final CloseEvent e)
		{
			logger.log(INFO, "attached link was closed ({0})", e.getReason());
			detach();
		}
	}

	private static final int GROUP_READ = 0x00;
	private static final int GROUP_RESPONSE = 0x40;
	private static final int GROUP_WRITE = 0x80;

	private final KNXNetworkLink lnk;
	private final NetworkLinkListener lnkListener = new NLListener();
	private final SecureApplicationLayer sal;
	private final boolean useGoDiagnostics;
	private final EventListeners<ProcessListener> listeners;

	private final Map<GroupAddress, FrameEvent> indications = new HashMap<>();
	private static final FrameEvent NoResponse = new FrameEvent(ProcessCommunicatorImpl.class, (CEMI) null);
	private final Map<GroupAddress, AtomicInteger> readers = new HashMap<>();

	private volatile Priority priority = Priority.LOW;
	private volatile Duration responseTimeout = Duration.ofSeconds(5);
	private volatile boolean detached;
	private final Logger logger;

	/**
	 * Creates a new process communicator attached to the supplied KNX network link.
	 * For secure process communication, {@link Security#defaultInstallation} is used.
	 *
	 * @param link network link used for communication with a KNX network
	 * @throws KNXLinkClosedException if the network link is closed
	 */
	public ProcessCommunicatorImpl(final KNXNetworkLink link) throws KNXLinkClosedException {
		this(link, Security.defaultInstallation(), true);
	}

	/**
	 * Creates a new process communicator attached to the supplied KNX network link, using {@code security} for secure
	 * process communication if required.
	 *
	 * @param link network link used for communication with a KNX network
	 * @param security security to use for secure process communication
	 * @param useGoDiagnostics {@code true} to use Group Object Diagnostics for outgoing KNX Data Secure messages,
	 *        {@code false} to directly secure with KNX Data Secure where encryption is required
	 * @throws KNXLinkClosedException
	 */
	public ProcessCommunicatorImpl(final KNXNetworkLink link, final Security security, final boolean useGoDiagnostics)
			throws KNXLinkClosedException {
		this(link, new SecureApplicationLayer(link, security), useGoDiagnostics);
	}

	/**
	 * Creates a new process communicator using the supplied secure application layer, attached to the supplied KNX
	 * network link.
	 *
	 * @param link network link used for communication with a KNX network
	 * @param sal secure application layer
	 * @throws KNXLinkClosedException if the network link is closed
	 */
	public ProcessCommunicatorImpl(final KNXNetworkLink link, final SecureApplicationLayer sal)
			throws KNXLinkClosedException {
		this(link, sal, true);
	}

	/**
	 * Creates a new process communicator using the supplied secure application layer, attached to the supplied KNX
	 * network link. This constructor allows to specify the communication behavior with respect to KNX Data Secure,
	 * whether to use Group Object Diagnostics for outgoing messages or not.
	 *
	 * @param link network link used for communication with a KNX network
	 * @param sal secure application layer
	 * @param useGoDiagnostics {@code true} to use Group Object Diagnostics for outgoing KNX Data Secure messages,
	 *        {@code false} to directly secure with KNX Data Secure where encryption is required
	 * @throws KNXLinkClosedException if the network link is closed
	 */
	public ProcessCommunicatorImpl(final KNXNetworkLink link, final SecureApplicationLayer sal,
			final boolean useGoDiagnostics) throws KNXLinkClosedException {
		if (!link.isOpen())
			throw new KNXLinkClosedException(
					"cannot initialize process communication using closed link " + link.getName());
		logger = LogService.getLogger("calimero.process.communication " + link.getName());
		lnk = link;
		this.sal = sal;
		this.useGoDiagnostics = useGoDiagnostics;

		listeners = new EventListeners<>(logger);
		sal.addListener(lnkListener);
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
	public void addProcessListener(final ProcessListener l)
	{
		listeners.add(l);
	}

	@Override
	public void removeProcessListener(final ProcessListener l)
	{
		listeners.remove(l);
	}

	@Override
	public boolean readBool(final GroupAddress dst) throws KNXTimeoutException, KNXRemoteException,
		KNXLinkClosedException, KNXFormatException, InterruptedException
	{
		final byte[] apdu = readFromGroup(dst, priority, 0, 0);
		final DPTXlatorBoolean t = new DPTXlatorBoolean(DPTXlatorBoolean.DPT_BOOL);
		extractGroupASDU(apdu, t);
		return t.getValueBoolean();
	}

	@Override
	public void write(final GroupAddress dst, final boolean value)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		try {
			final DPTXlatorBoolean t = new DPTXlatorBoolean(DPTXlatorBoolean.DPT_BOOL);
			t.setValue(value);
			write(dst, priority, t);
		}
		catch (final KNXFormatException ignore) {}
	}

	@Override
	public int readUnsigned(final GroupAddress dst, final String scale) throws KNXTimeoutException,
		KNXRemoteException, KNXLinkClosedException, KNXFormatException, InterruptedException
	{
		final byte[] apdu = readFromGroup(dst, priority, 1, 1);
		final DPTXlator8BitUnsigned t = new DPTXlator8BitUnsigned(scale);
		extractGroupASDU(apdu, t);
		return t.getValueUnsigned();
	}

	@Override
	public void write(final GroupAddress dst, final int value, final String scale)
		throws KNXTimeoutException, KNXFormatException, KNXLinkClosedException
	{
		final DPTXlator8BitUnsigned t = new DPTXlator8BitUnsigned(scale);
		t.setValue(value);
		write(dst, priority, t);
	}

	@Override
	public int readControl(final GroupAddress dst) throws KNXTimeoutException, KNXRemoteException,
		KNXLinkClosedException, KNXFormatException, InterruptedException
	{
		final byte[] apdu = readFromGroup(dst, priority, 0, 0);
		final DPTXlator3BitControlled t = new DPTXlator3BitControlled(
				DPTXlator3BitControlled.DPT_CONTROL_DIMMING);
		extractGroupASDU(apdu, t);
		return t.getValueSigned();
	}

	@Override
	public void write(final GroupAddress dst, final boolean control, final int stepcode)
		throws KNXTimeoutException, KNXFormatException, KNXLinkClosedException
	{
		final DPTXlator3BitControlled t = new DPTXlator3BitControlled(
				DPTXlator3BitControlled.DPT_CONTROL_DIMMING);
		t.setValue(control, stepcode);
		write(dst, priority, t);
	}

	@Override
	public void write(final GroupAddress dst, final double value, final boolean use4ByteFloat)
		throws KNXTimeoutException, KNXFormatException, KNXLinkClosedException
	{
		if (use4ByteFloat) {
			final DPTXlator4ByteFloat t = new DPTXlator4ByteFloat(DPTXlator4ByteFloat.DPT_TEMPERATURE_DIFFERENCE);
			t.setValue((float) value);
			write(dst, priority, t);
		}
		else {
			final DPTXlator2ByteFloat t = new DPTXlator2ByteFloat(DPTXlator2ByteFloat.DPT_RAIN_AMOUNT);
			t.setValue(value);
			write(dst, priority, t);
		}
	}

	@Override
	public double readFloat(final GroupAddress dst) throws KNXTimeoutException, KNXRemoteException,
		KNXLinkClosedException, KNXFormatException, InterruptedException {
		final byte[] apdu = readFromGroup(dst, priority, 2, 4);
		final DPTXlator t = apdu.length == 6 ? new DPTXlator4ByteFloat(DPTXlator4ByteFloat.DPT_TEMPERATURE_DIFFERENCE)
				: new DPTXlator2ByteFloat(DPTXlator2ByteFloat.DPT_RAIN_AMOUNT);
		extractGroupASDU(apdu, t);
		return t.getNumericValue();
	}

	@Override
	public String readString(final GroupAddress dst) throws KNXTimeoutException, KNXRemoteException,
		KNXLinkClosedException, KNXFormatException, InterruptedException
	{
		final byte[] apdu = readFromGroup(dst, priority, 0, 14);
		final DPTXlatorString t = new DPTXlatorString(DPTXlatorString.DPT_STRING_8859_1);
		extractGroupASDU(apdu, t);
		return t.getValue();
	}

	@Override
	public void write(final GroupAddress dst, final String value)
		throws KNXTimeoutException, KNXFormatException, KNXLinkClosedException
	{
		final DPTXlatorString t = new DPTXlatorString(DPTXlatorString.DPT_STRING_8859_1);
		t.setValue(value);
		write(dst, priority, t);
	}

	@Override
	public void write(final GroupAddress dst, final DPTXlator value)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		write(dst, priority, value);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * If {@code dp} has no {@link DPT} set, this method returns a hexadecimal representation
	 * of the ASDU.
	 */
	@Override
	public String read(final Datapoint dp) throws KNXException, InterruptedException
	{
		final byte[] apdu = readFromGroup(dp.getMainAddress(), dp.getPriority(), 0, 14);
		if (dp.getDPT() == null)
			return DataUnitBuilder.toHex(DataUnitBuilder.extractASDU(apdu), " ");
		final DPTXlator t = TranslatorTypes.createTranslator(dp.getMainNumber(), dp.getDPT());
		extractGroupASDU(apdu, t);
		return t.getValue();
	}

	@Override
	public void write(final Datapoint dp, final String value) throws KNXException
	{
		final DPTXlator t = TranslatorTypes.createTranslator(dp.getMainNumber(), dp.getDPT());
		t.setValue(value);
		write(dp.getMainAddress(), dp.getPriority(), t);
	}

	@Override
	public double readNumeric(final Datapoint dp) throws KNXException, InterruptedException
	{
		final byte[] apdu = readFromGroup(dp.getMainAddress(), dp.getPriority(), 0, 8);
		if (dp.getMainNumber() == 0 && dp.getDPT() == null) {
			apdu[1] &= 0x3f;
			// we're parsing the asdu as signed long
			long l = 0;
			final int offset = apdu.length == 2 ? 1 : 2;
			for (int i = offset; i < apdu.length; i++)
				l = (l << 8) + (apdu[i] & 0xff);
			return l;
		}
		final DPTXlator t = TranslatorTypes.createTranslator(dp.getMainNumber(), dp.getDPT());
		extractGroupASDU(apdu, t);
		return t.getNumericValue();
	}

	@Override
	public KNXNetworkLink detach()
	{
		// if we synchronize on method we would take into account
		// a worst case blocking of response timeout seconds
		synchronized (lnkListener) {
			// wait of response time seconds
			if (detached)
				return null;
			detached = true;
		}
		lnk.removeLinkListener(lnkListener);
		sal.close();
		fireDetached();
		logger.log(DEBUG, "detached from link {0}", lnk.getName());
		return lnk;
	}

	private void write(final GroupAddress dst, final Priority p, final DPTXlator t)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		if (detached)
			throw new IllegalStateException("process communicator detached");
		try {
			send(dst, p, GROUP_WRITE, t);
			logger.log(TRACE, "group write to {0} succeeded", dst);
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new KNXTimeoutException("interrupted", e);
		}
	}

	private byte[] readFromGroup(final GroupAddress dst, final Priority p,
		final int minASDULen, final int maxASDULen) throws KNXTimeoutException,
			KNXInvalidResponseException, KNXLinkClosedException, InterruptedException
	{
		if (detached)
			throw new IllegalStateException("process communicator detached");
		try {
			synchronized (indications) {
				readers.computeIfAbsent(dst, v -> new AtomicInteger()).incrementAndGet();
				indications.putIfAbsent(dst, NoResponse);
			}
			send(dst, p, GROUP_READ, null);
			logger.log(TRACE, "sent group read request to {0}", dst);
			return waitForResponse(dst, minASDULen + 2, maxASDULen + 2);
		}
		finally {
			synchronized (indications) {
				final boolean none = readers.get(dst).decrementAndGet() == 0;
				readers.compute(dst, (k, v) -> none ? null : v);
				indications.compute(dst, (k, v) -> none ? null : v);
			}
		}
	}

	protected void send(final GroupAddress dst, final Priority p, final int service, final DPTXlator t)
			throws KNXTimeoutException, KNXLinkClosedException, InterruptedException {
		if (useGoDiagnostics && sal.security().groupKeys().containsKey(dst)) {
			try {
				final var future = sal.writeGroupObjectDiagnostics(dst, t == null ? new byte[0] : t.getData());
				final var returnCode = future.get();
				if (returnCode != ReturnCode.Success)
					logger.log(WARNING, "{0} {1}", dst, returnCode);
			}
			catch (final ExecutionException e) {
				logger.log(WARNING, "waiting for GO diagnostics", e.getCause());
			}
		}
		else {
			final var src = lnk.getKNXMedium().getDeviceAddress();
			final var plainApdu = createGroupAPDU(service, t);
			final byte[] apdu = sal.secureGroupObject(src, dst, plainApdu).orElse(plainApdu);
			lnk.sendRequestWait(dst, p, apdu);
		}
	}

	private byte[] waitForResponse(final GroupAddress from, final int minAPDU, final int maxAPDU)
		throws KNXInvalidResponseException, KNXTimeoutException, InterruptedException
	{
		long remaining = responseTimeout.toMillis();
		final long end = System.currentTimeMillis() + remaining;
		synchronized (indications) {
			while (remaining > 0) {
				final FrameEvent e = indications.get(from);
				if (e == NoResponse) {
					indications.wait(remaining);
					remaining = end - System.currentTimeMillis();
				}
				else {
					final byte[] d = e.getFrame().getPayload();
					final int len = d.length;
					// validate length of response we're waiting for
					if (len >= minAPDU && len <= maxAPDU)
						return d;

					final String s = "APDU response length " + len + " bytes, expected " + minAPDU + " to " + maxAPDU;
					logger.log(ERROR, "received group read response from {0} with {1}", from, s);
					throw new KNXInvalidResponseException(s);
				}
			}
		}
		throw new KNXTimeoutException("timeout waiting for group read response from " + from);
	}

	private void fireDetached()
	{
		final DetachEvent e = new DetachEvent(this);
		listeners.fire(l -> l.detached(e));
	}

	// createGroupAPDU and extractGroupASDU helper would actually better fit
	// into to DataUnitBuilder, but moved here to avoid DPT dependencies

	/**
	 * Creates a group service application layer protocol data unit containing all items of a DPT
	 * translator.
	 * <p>
	 * The transport layer bits in the first byte (TL / AL control field) are set 0. The maximum
	 * length used for the ASDU is not checked.<br>
	 * For DPTs occupying &lt;= 6 bits in length the optimized (compact) group write / response
	 * format layout is used.
	 *
	 * @param service application layer group service code
	 * @param t DPT translator with items to put into ASDU
	 * @return group APDU as byte array
	 */
	private static byte[] createGroupAPDU(final int service, final DPTXlator t)
	{
		// check for group read
		if (service == GROUP_READ)
			return new byte[2];
		// only group response and group write are allowed
		if (service != GROUP_RESPONSE && service != GROUP_WRITE)
			throw new KNXIllegalArgumentException("not an APDU group service");
		// determine if data starts at byte offset 1 (optimized) or 2 (default)
		final int offset = t.getItems() == 1 && t.getTypeSize() == 0 ? 1 : 2;
		final byte[] buf = new byte[t.getItems() * Math.max(1, t.getTypeSize()) + offset];
		buf[0] = (byte) (service >> 8);
		buf[1] = (byte) service;
		return t.getData(buf, offset);
	}

	/**
	 * Extracts the service data unit of an application layer protocol data unit into a DPT
	 * translator.
	 * <p>
	 * The whole service data unit is taken as data for translation. If the length of the supplied
	 * {@code apdu} is 2, a length-optimized (compact) group APDU format layout is assumed.<br>
	 * On return of this method, the supplied translator contains the DPT items from the ASDU.
	 *
	 * @param apdu application layer protocol data unit, 2 &lt;= apdu.length
	 * @param t the DPT translator to fill with the ASDU
	 */
	private static void extractGroupASDU(final byte[] apdu, final DPTXlator t)
	{
		if (apdu.length < 2)
			throw new KNXIllegalArgumentException("minimum APDU length is 2 bytes");
		t.setData(apdu, apdu.length == 2 ? 1 : 2);
	}
}
