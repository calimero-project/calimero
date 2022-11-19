/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2014, 2022 B. Malinowsky

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

package tuwien.auto.calimero.serial;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.System.Logger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.Connection;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAckTimeoutException;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXListener;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIBusMon;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.internal.Executor;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.serial.spi.SerialCom;

/**
 * Provides a connection with a TP-UART-IC controller for transparent communication with a KNX TP1 network. The
 * connection supports cEMI L-Data communication and busmonitor mode.<br>
 * The host establishes a connection over a serial port, using any identifier recognized and supported by the serial
 * adapter and the operating system.
 * <p>
 * Interruption policy: any blocking sends are cancelled.
 *
 * @author B. Malinowsky
 */
public class TpuartConnection implements Connection<byte[]>
{
	// UART services

	private static final int Reset_req = 0x01;
	private static final int Reset_ind = 0x03;

	// we can use this service to distinguish TP-UART 1/2
	// TP-UART 1 doesn't support this service
//	private static final int ProductId_req = 0x20;

	// the ProductId_res sucks, as it is specified without msg code
	// | Bit 7 - 5 | Bit 4 - 0 |
	// |  Prod. Id |  Rev. no  |
	// TP-UART 2 Release a
//	private static final int V2ReleaseA = 0b01000001;

	private static final int State_req = 0x02;
	private static final int State_ind = 0x07;

	private static final int ActivateBusmon = 0x05;

	private static final int LData_con = 0x0b; // MSB is pos/neg confirm
	private static final int AckInfo = 0x10;

	private static final int LDataStart = 0x80; // plus L_Data byte index
	private static final int LDataEnd = 0x40; // plus L_Data.length

	// TP1 frame type constants

	private static final int AlwaysSet = 0x10;
	private static final int StdFrameFormat = 0x80 | AlwaysSet;
	private static final int ExtFrameFormat = AlwaysSet;
	private static final int RepeatFlag = 0x20;

	// Short acks in bus monitor mode
	private static final int Ack = 0xcc;
	private static final int Nak = 0x0c;
	private static final int Busy = 0xc0;

	// TP-UART send

	// time interval to check on TP UART state
	private static final long UartStateReadInterval = 5_000_000; // [us]

	private static final int UartBaudRate = 19_200;
	private static final int Tp1BaudRate = 9_600;

	private static final int OneBitTime = (int) Math.ceil(1d / Tp1BaudRate * 1_000_000);
	private static final int BitTimes_50 = 50 * OneBitTime; // [us]

	private static final int MaxSendAttempts = 4;


	private final String portId;
	private final SerialCom adapter;
	private final OutputStream os;
	private final InputStream is;

	private final Receiver receiver = new Receiver();

	private final ReentrantLock lock = new ReentrantLock();
	private final Condition con = lock.newCondition();
	private final Condition enterIdle = lock.newCondition();

	private volatile boolean idle;

	// NYI compare to received frame for .con, or just remove
	private volatile byte[] req;

	private volatile boolean busmon;
	private volatile int busmonSequence;

	private final EventListeners<KNXListener> listeners = new EventListeners<>();

	private final Set<KNXAddress> addresses = Collections.synchronizedSet(new HashSet<>());
	private final Map<KNXAddress, Long> sending = new ConcurrentHashMap<>();

	private final Logger logger;

	/**
	 * Creates a new TP-UART connection using communication port {@code portId}, expecting a collection of KNX
	 * addresses for which the host shall acknowledge TP1 frame reception.
	 *
	 * @param portId the identifier of the communication port
	 * @param acknowledge a (possibly empty) collection of KNX addresses this endpoint shall issue a positive
	 *        acknowledgement for, on receiving a valid TP1 frame with its destination address being an element in
	 *        {@code acknowledge}. By default, this endpoint also won't acknowledge the default individual
	 *        address 0.2.ff on the TP1 network.
	 * @throws KNXException on error opening the communication port, or initializing the TP-UART controller
	 */
	public TpuartConnection(final String portId, final Collection<? extends KNXAddress> acknowledge) throws KNXException
	{
		this.portId = portId;
		logger = LogService.getAsyncLogger("calimero.serial.tpuart:" + portId);
		adapter = LibraryAdapter.open(logger, portId, UartBaudRate, 0);
		os = adapter.outputStream();
		is = adapter.inputStream();

		addresses.add(GroupAddress.Broadcast);
		addresses.addAll(acknowledge);

		Executor.execute(receiver, "Calimero TP-UART receiver");
		try {
			reset();
		}
		catch (final IOException e) {
			closeResources();
			throw new KNXPortClosedException("on resetting TP-UART controller", portId, e);
		}
		if (!waitForInitialUartState()) {
			closeResources();
			throw new KNXPortClosedException("timeout waiting for initial TP-UART state", portId);
		}
	}

	private boolean waitForInitialUartState() {
		logger.log(TRACE, "wait for initial TP-UART state");
		long now = System.nanoTime();
		final long end = now + 1_000_000_000L;
		try {
			while (now < end) {
				if (receiver.lastUartState != 0)
					return true;

				Thread.sleep(10);
				now = System.nanoTime();
			};
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		return false;
	}

	/**
	 * Adds the specified event listener {@code l} to receive events from this connection. If {@code l} was
	 * already added as listener, no action is performed.
	 *
	 * @param l the listener to add
	 */
	@Override
	public final void addConnectionListener(final KNXListener l)
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
	public final void removeConnectionListener(final KNXListener l)
	{
		listeners.remove(l);
	}

	@Override
	public String name()
	{
		return portId;
	}

	/**
	 * Activate busmonitor mode, the TP-UART controller is set completely passive.
	 *
	 * @throws IOException on I/O error
	 */
	public void activateBusmonitor() throws IOException
	{
		logger.log(DEBUG, "activate TP-UART busmonitor");
		os.write(ActivateBusmon);
		busmonSequence = 0;
		busmon = true;
	}

	/**
	 * Adds an address to the list of addresses acknowledged on the bus.
	 *
	 * @param ack the address to acknowledge
	 */
	public final void addAddress(final KNXAddress ack)
	{
		addresses.add(ack);
	}

	/**
	 * Removes an address from the list of addresses acknowledged on the bus.
	 *
	 * @param ack the address to no further acknowledge
	 */
	public final void removeAddress(final KNXAddress ack)
	{
		addresses.remove(ack);
	}

	@Override
	public void send(final byte[] frame, final BlockingMode blockingMode)
			throws KNXPortClosedException, KNXAckTimeoutException, InterruptedException {
		send(frame, blockingMode != BlockingMode.NonBlocking);
	}

	/**
	 * Sends a cEMI L-Data frame, either waiting for confirmation or non-blocking. Sending is not-permitted in
	 * busmonitor mode. A cEMI frame for TP1 does not require any additional information, any additional information is
	 * ignored.
	 *
	 * @param frame cEMI L-Data msg as byte array
	 * @param waitForCon wait for L_Data.con (blocking) or not (non-blocking)
	 * @throws KNXPortClosedException on closed communication port
	 * @throws KNXAckTimeoutException on send/receive timeout (or if no ACK from the bus was received)
	 * @throws InterruptedException on thread interrupt, a send waiting for L-Data confirmation will be cancelled
	 */
	// TODO sync concurrent sends
	public void send(final byte[] frame, final boolean waitForCon)
		throws KNXPortClosedException, KNXAckTimeoutException, InterruptedException
	{
		try {
			final byte[] tp1Frame = cEmiToTP1(frame);
			final byte[] data = toUartServices(tp1Frame);
			logger.log(TRACE, () -> "create UART services " + DataUnitBuilder.toHex(data, " "));
			req = frame.clone();

			// force cool down period if we got a crispy chip
			final long coolDownMillis = (receiver.coolDownUntil - System.nanoTime()) / 1_000_000;
			if (coolDownMillis > 0)
				Thread.sleep(coolDownMillis);

			final long start = System.nanoTime();
			final boolean group = (frame[3] & 0x80) == 0x80;
			if (group)
				sending.put(new GroupAddress(new byte[] { frame[6], frame[7] }), start);

			final boolean logReadyForSending = !idle;
			lock.lock();
			try {
				if (!idle)
					enterIdle.await();
			}
			finally {
				lock.unlock();
			}
			if (logReadyForSending)
				logger.log(TRACE, "UART ready for sending after {0} us", (System.nanoTime() - start) / 1000);
			logger.log(DEBUG, "write UART services, {0}", (waitForCon ? "waiting for .con" : "non-blocking"));

			lock.lock();
			try {
				os.write(data);
				if (!waitForCon)
					return;
				if (waitForCon(tp1Frame.length))
					return;
			}
			finally {
				lock.unlock();
			}
			throw new KNXAckTimeoutException("no ACK for L-Data.con");
		}
		catch (final InterruptedIOException e) {
			throw new InterruptedException(e.getMessage());
		}
		catch (final IOException e) {
			close();
			throw new KNXPortClosedException("I/O error", portId, e);
		}
		finally {
			req = null;
		}
	}

	@Override
	public void close()
	{
		close(CloseEvent.USER_REQUEST, "user request");
	}

	private void close(final int origin, final String reason)
	{
		// best-effort, as we might already have hit an I/O error
		try {
			reset();
		}
		catch (final InterruptedIOException e) {
			Thread.currentThread().interrupt();
		}
		catch (final IOException ignore) {}
		closeResources();
		fireConnectionClosed(origin, reason);
	}

	private void closeResources() {
		receiver.quit();
		adapter.close();
	}

	private void fireConnectionClosed(final int origin, final String reason)
	{
		final CloseEvent ce = new CloseEvent(this, origin, reason);
		listeners.fire(l -> l.connectionClosed(ce));
	}

	private void reset() throws IOException
	{
		logger.log(DEBUG, "reset TP-UART controller");
		busmon = false;
		busmonSequence = 0;
		os.write(Reset_req);
	}

	// returns a TP1 std or ext frame
	private static byte[] cEmiToTP1(final byte[] frame)
	{
		// set frame type to std/ext
		final int stdMaxApdu = 15;
		// skip 1 byte mc + 1 byte add.info length + any add.info
		final int skipToCtrl1 = 2 + frame[1] & 0xff;
		final int cemiPrefix = skipToCtrl1 + 8;

		final boolean extended = (frame[skipToCtrl1] & 0x80) == 0;
		final boolean std = !extended && frame.length <= cemiPrefix + stdMaxApdu;

		final byte[] tp1;
		if (std) {
			// total length = frame length - skipToCtrl1 - ctrl2 + 1 byte checksum
			tp1 = new byte[frame.length - skipToCtrl1];
			int i = 0;
			// set upper 6 bits of ctrl1 field, ensure not repeated std frame
			tp1[i++] = (byte) ((frame[skipToCtrl1] & 0xfc) | StdFrameFormat | RepeatFlag);
			// src
			tp1[i++] = frame[skipToCtrl1 + 2];
			tp1[i++] = frame[skipToCtrl1 + 3];
			// dst
			tp1[i++] = frame[skipToCtrl1 + 4];
			tp1[i++] = frame[skipToCtrl1 + 5];
			// address type, npci, length
			final int len = frame[skipToCtrl1 + 6];
			tp1[i++] = (byte) ((frame[skipToCtrl1 + 1] & 0xf0) | len);
			// tpci
			tp1[i++] = frame[skipToCtrl1 + 7];
			// apdu
			for (int k = 0; k < len; k++)
				tp1[i++] = frame[cemiPrefix + k];
		}
		else {
			// total length = frame length - skipToCtrl1 + 1 byte checksum
			final int length = frame.length - skipToCtrl1 + 1;
			if (length > 64)
				throw new KNXIllegalArgumentException("L-Data frame length " + length + " > max. 64 bytes for TP-UART");

			tp1 = new byte[length];
			for (int i = skipToCtrl1; i < frame.length; i++)
				tp1[i - skipToCtrl1] = frame[i];

			// ensure not repeated ext frame
			tp1[0] &= ~StdFrameFormat;
			tp1[0] |= ExtFrameFormat | RepeatFlag;
		}
		// last byte is checksum
		tp1[tp1.length - 1] = (byte) checksum(tp1);
		return tp1;
	}

	private static byte[] toUartServices(final byte[] tp1)
	{
		final ByteArrayOutputStream data = new ByteArrayOutputStream(tp1.length * 2);
		for (int i = 0; i < tp1.length - 1; i++) {
			data.write(LDataStart | i);
			data.write(tp1[i]);
		}
		// write end data with frame checksum
		data.write(LDataEnd | tp1.length - 1);
		data.write(tp1[tp1.length - 1]);

		return data.toByteArray();
	}

	private boolean waitForCon(final int frameLen) throws InterruptedException
	{
		// time from start-bit to start-bit of inner frame consecutive characters, 13 bit times [us]
		final int innerFrameChar = 13 * OneBitTime;
		final int bitTimes_15 = 15 * OneBitTime; // [us]
		final int maxExchangeTimeout = MaxSendAttempts * (BitTimes_50 + frameLen * innerFrameChar + 2 * bitTimes_15) / 1000;

		final long start = System.nanoTime();
		final boolean rcvdCon = con.await(maxExchangeTimeout, TimeUnit.MILLISECONDS);
		final long wait = (System.nanoTime() - start) / 1_000_000;
		if (rcvdCon)
			logger.log(TRACE, "ACK received after {0} ms", wait);
		else
			logger.log(DEBUG, "no ACK received after {0} ms", wait);
		return rcvdCon;
	}

	private static int checksum(final byte[] frame)
	{
		int cs = 0;
		for (final byte b : frame)
			cs ^= b;
		return ~cs;
	}

	private boolean isValidChecksum(final byte[] frame)
	{
		final byte[] copy = Arrays.copyOf(frame, frame.length - 1);
		final int cs = checksum(copy);
		final int expected = frame[frame.length - 1];
		final boolean valid = expected == cs;
		if (!valid)
			logger.log(WARNING, "invalid L-Data checksum 0x{0}, expected 0x{1}", Integer.toHexString(cs & 0xff),
					Integer.toHexString(expected & 0xff));
		return valid;
	}

	// Stores the currently used max. inter-byte delay, to also be available for subsequent tpuart connections.
	// Defaults to 50 bit times [us]
	private static final AtomicInteger maxInterByteDelay = new AtomicInteger(BitTimes_50);
	static {
		final var key = "calimero.serial.tpuart.maxInterByteDelay";
		try {
			final var delay = System.getProperty(key);
			if (delay != null) {
				final int value = Integer.parseUnsignedInt(delay);
				maxInterByteDelay.set(value);
				LogService.getLogger("calimero.serial.tpuart").log(INFO, "using {0} of {1} us", key, value);
			}
		}
		catch (final RuntimeException e) {
			LogService.getLogger("calimero.serial.tpuart").log(WARNING, "on checking property {0}", key, e);
		}
	}

	private final class Receiver implements Runnable
	{
		private volatile boolean quit;
		private volatile Thread thread;

		private final ByteArrayOutputStream in = new ByteArrayOutputStream();
		private long lastRead;
		private boolean extFrame;
		private boolean frameAcked;

		private byte[] lastReceived = new byte[0];
		volatile long lastUartState; // [us]
		private boolean uartStatePending;

		private int maxDelay = maxInterByteDelay.get();
		private int consecutiveFrameDrops = -1;

		private long coolDownUntil;


		@Override
		public void run()
		{
			thread = Thread.currentThread();

			// at first drain rx queue of any old frames
			// most likely, flushes out the reset.ind corresponding to our init reset, but that's ok
			int drained = 0;
			try {
				while (is.read() != -1)
					drained++;
			}
			catch (final IOException ignore) {}
			logger.log(TRACE, "drained rx queue ({0} bytes)", drained);

			long enterIdleTimestamp = 0; // [ns]
			while (!quit) {
				try {
					final long start = System.nanoTime();
					final int c = is.read();

					if (c == -1) {
						checkUartState();

						// we transition to idle state after some time of inactivity, and notify a waiting sender
						final long inactivity = 10_000; // [us]
						if (enterIdleTimestamp == 0)
							enterIdleTimestamp = start;
						else if (coolDownUntil > start) {
							// we received a temperature warning and are in cool down mode (no sending allowed)
							// throttle busy wait on input stream
							Thread.sleep(1);
						}
						else if ((start - enterIdleTimestamp) / 1000 > inactivity) {
							lock.lock();
							try {
								idle = true;
								enterIdle.signal();
							}
							finally {
								lock.unlock();
							}
						}
						continue;
					}

					final long idlePeriod = (start - enterIdleTimestamp) / 1000;
					if (enterIdleTimestamp != 0 && idlePeriod > 100_000)
						logger.log(TRACE, "receiver woke from extended idle period of {0} us", idlePeriod);
					idle = false;
					enterIdleTimestamp = 0;

					if (parseFrame(c) || isLDataCon(c) || isUartStateInd(c))
						; // nothing to do
					else if (c == Reset_ind) {
						uartStatePending = false;
						logger.log(DEBUG, "TP-UART reset.ind");
					}

					final long loop = System.nanoTime() - start;
					logger.log(TRACE, "loop time = {0} us", loop / 1000);
				}
				catch (final RuntimeException e) {
					logger.log(WARNING, "continue after internal error in receiver loop", e);
				}
				catch (final InterruptedException e) {}
				catch (final IOException e) {
					if (!quit)
						close(CloseEvent.INTERNAL, "receiver communication failure, " + e.toString());
					break;
				}
			}
		}

		void quit()
		{
			quit = true;
			final var t = thread;
			if (t == null)
				return;
			t.interrupt();
			if (Thread.currentThread() == t)
				return;
			try {
				t.join(50);
			}
			catch (final InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}

		private int maxInterByteDelay()
		{
			// cond: consecutively losing 4 frames (1 msg w/ 1 .ind + 2 .ind repetitions, and 1st .ind of next msg)
			if (consecutiveFrameDrops >= 3) {
				maxDelay = maxInterByteDelay.accumulateAndGet(Math.min(maxDelay + 500, 20_000), Math::max);
				logger.log(WARNING, "{0} partial frames discarded, increase max. inter-byte delay to {1} us",
						consecutiveFrameDrops + 1, maxDelay);
				consecutiveFrameDrops = -1;
			}
			return maxDelay;
		}

		private boolean parseFrame(final int c) throws IOException
		{
			final long now = System.nanoTime() / 1000;
			int size = in.size();
			if (size > 0) {
				// empty current buffer if we didn't receive data for some time
				final int minLength = extFrame ? 7 : 6;
				final long diff = now - lastRead;
				if (size < minLength && diff > maxInterByteDelay()) {
					resetReceiveBuffer(c, diff);
					size = 0;
				}
				else if (size >= minLength && diff > 4 * maxInterByteDelay()) {
					resetReceiveBuffer(c, diff);
					size = 0;
				}
			}

			if (size > 0) {
				in.write(c);
				lastRead = now;
				final int minLength = extFrame ? 7 : 6;
				if (size + 1 >= minLength) {
					final byte[] frame = in.toByteArray();
					ack(frame);

					// check if we got the expected frame size
					final int total;
					if (extFrame)
						total = 8 + (frame[6] & 0x3f) + 1;
					else
						total = 7 + (frame[5] & 0x0f) + 1;

					if (frame.length >= total) {
						try {
							final byte[] data = in.toByteArray();
							logger.log(DEBUG, "received TP1 L-Data (length {0}): {2}", frame.length,
									DataUnitBuilder.toHex(data, " "));
							consecutiveFrameDrops = -1;
							if (busmon) {
								fireFrameReceived(createBusmonInd(data));
							}
							else {
								// check repetition of a directly preceding correctly received frame
								final boolean repeated = (data[0] & RepeatFlag) == 0;
								if (repeated && Arrays.equals(lastReceived, 0, lastReceived.length - 2, frame, 0,
										data.length - 2)) {
									logger.log(DEBUG, "ignore repetition of directly preceding correctly received frame");
								}
								else {
									lastReceived = data.clone();
									lastReceived[0] &= ~RepeatFlag; // set repeat flag

									fireFrameReceived(createLDataInd(data));
								}
							}
						}
						catch (final Exception e) {
							logger.log(ERROR, "error creating {0} from TP1 data (length {2}): {3}",
									busmon ? "Busmon.ind" : "L-Data", frame.length, DataUnitBuilder.toHex(frame, " "),
									e);
						}
						finally {
							in.reset();
						}
					}
				}
			}
			else if (isLDataStart(c)) {
				lastRead = now;
				in.reset();
				in.write(c);
				frameAcked = false;
				final byte[] minBytes = new byte[extFrame ? 6 : 5];
				final int read = is.read(minBytes);
				final long initialMinBytes = (System.nanoTime() / 1000 - lastRead);
				if (read > 0) {
					in.write(minBytes, 0, read - 1);
					lastRead = System.nanoTime() / 1000;
					parseFrame(minBytes[read - 1]);
				}
				logger.log(TRACE, "finished reading {0} bytes after {1} us", read, initialMinBytes);
			}
			// busmon mode only: short acks
			else if (c == Ack || c == Nak || c == Busy)
				fireFrameReceived(createBusmonInd(new byte[] { (byte) c }));
			else
				return false;
			return true;
		}

		private void resetReceiveBuffer(final int c, final long diff) {
			final byte[] buf = in.toByteArray();
			in.reset();
			logger.log(DEBUG, "reset receive buffer after {0} us, char 0x{1}, discard partial frame (length {2}) {3}",
					diff, Integer.toHexString(c), buf.length, DataUnitBuilder.toHex(buf, " "));
			consecutiveFrameDrops++;
		}

		private void checkUartState() throws IOException {
			final long now = System.nanoTime() / 1000;
			if (lastUartState + UartStateReadInterval < now) {
				if (lastUartState != 0 && now > lastUartState + 2 * UartStateReadInterval + 100_000)
					close(CloseEvent.INTERNAL, "communication not possible, TP1 medium not connected?");
				else
					readUartState();
			}
		}

		private void readUartState() throws IOException
		{
			if (uartStatePending)
				return;
			uartStatePending = true;
			os.write(State_req);
		}

		private boolean isUartStateInd(final int c)
		{
			if (!uartStatePending)
				return false;
			final boolean ind = (c & State_ind) == State_ind;
			if (!ind)
				return false;
			uartStatePending = false;
			lastUartState = System.nanoTime() / 1000;
			final boolean slaveCollision = (c & 0x80) == 0x80;
			final boolean rxError = (c & 0x40) == 0x40; // checksum, parity, bit error
			final boolean txError = (c & 0x20) == 0x20; // send 0, receive 1
			final boolean protError = (c & 0x10) == 0x10; // illegal ctrl byte
			final boolean tempWarning = (c & 0x08) == 0x08; // too hot

			final boolean info = slaveCollision || rxError || txError || protError || tempWarning;
			logger.log(info ? INFO : TRACE, "TP-UART status: Temp. {0}{1}{2}{3}{4}",
					tempWarning ? "warning" : "OK", slaveCollision ? ", slave collision" : "",
					rxError ? ", receive error" : "", txError ? ", transmit error" : "",
					protError ? ", protocol error" : "");

			if (tempWarning) {
				coolDownUntil = System.nanoTime() + 1_000_000_000;
				logger.log(WARNING, "TP-UART high temperature warning! Sending is paused for 1 second ...");
			}
			return true;
		}

		private boolean isLDataCon(final int c)
		{
			final boolean con = (c & 0x7f) == LData_con;
			if (con) {
				final boolean pos = (c & 0x80) == 0x80;
				final String status = pos ? "positive" : "negative";
				logger.log(DEBUG, "{0} L_Data.con", status);
				onConfirmation(pos);
			}
			return con;
		}

		private boolean isLDataStart(final int c)
		{
			if ((c & 0x03) != 0)
				return false;
			final boolean start = (c & 0xd0) == StdFrameFormat || (c & 0xd0) == ExtFrameFormat;
			if (start) {
//				final boolean repeated = (c & RepeatFlag) == 0;
//				logger.log(TRACE, "start of frame 0x{0}, repeated = {1}", Integer.toHexString(c), repeated);
				extFrame = (c & 0xd0) == ExtFrameFormat;
			}
			return start;
		}

		// pre: we have a new .ind frame, length > 5
		// The ack service has to be sent at the latest 1.7 ms after receiving the
		// address-type bit of the L-Data.ind
		private void ack(final byte[] frame) throws IOException
		{
			if (busmon || frameAcked)
				return;
			final int addrOffset = extFrame ? 4 : 3;
			final byte[] addr = new byte[] { frame[addrOffset], frame[addrOffset + 1] };
			final int addrTypeOffset = extFrame ? 1 : 5;
			final boolean group = (frame[addrTypeOffset] & 0x80) == 0x80;
			final KNXAddress dst = group ? new GroupAddress(addr) : new IndividualAddress(addr);

			// We can answer as follows:
			// ACK: if we got addressed
			// NAK: we don't care about that, because the TP-UART checks that for us
			// Busy: we're never busy
			int ack = AckInfo;

			final long timestamp = sending.getOrDefault(dst, 0L);
			final boolean groupResponse = (System.nanoTime() - timestamp) < 3_000_000_000L;
			if (timestamp > 0 && !groupResponse)
				sending.remove(dst);

			final boolean oneOfUs = addresses.contains(dst) || groupResponse;
			if (oneOfUs) {
				ack |= 0x01;
				os.write(new byte[] { (byte) ack });
				logger.log(TRACE, "write ACK (0x{0}) for {1}", Integer.toHexString(ack), dst);
			}
			frameAcked = true;
		}

		// TODO We assemble a .con using our saved .req, and let the TP-UART L-Data frame bubble up
		// as .ind, which is useless. Use the received frame as L-Data.con, or throw it away.
		private void onConfirmation(final boolean pos)
		{
			// assemble a .con frame
			final byte[] frame = req;
			if (frame == null)
				return;
			frame[0] = CEMILData.MC_LDATA_CON;
			if (pos) {
				// set confirm bit to no error
				frame[2] &= 0xfe;
			}
			else {
				// set confirm bit to error
				frame[2] |= 0x01;
			}
			lock.lock();
			try {
				con.signalAll();
			}
			finally {
				lock.unlock();
			}
			fireFrameReceived(frame);
		}

		// create a cEMI L-Data from a TP1 frame
		private byte[] createLDataInd(final byte[] tp1)
		{
			return createLData(CEMILData.MC_LDATA_IND, tp1);
		}

		// create a cEMI L-Data from a TP1 frame
		private byte[] createLData(final int mc, final byte[] tp1)
		{
			if (!isValidChecksum(tp1))
				return null;

			final boolean std = (tp1[0] & StdFrameFormat) == StdFrameFormat;
			final byte[] ind = new byte[tp1.length + (std ? 2 : 1)];
			ind[0] = (byte) mc;
			// with TP1, there is no additional information, i.e., 2nd cEMI byte is always 0
			ind[1] = 0;
			if (std) {
				ind[2] = tp1[0];
				ind[3] = (byte) (tp1[5] & 0xf0);
				// src
				ind[4] = tp1[1];
				ind[5] = tp1[2];
				// dst
				ind[6] = tp1[3];
				ind[7] = tp1[4];
				// len
				final int len = tp1[5] & 0x0f;
				ind[8] = (byte) len;
				// tpci
				ind[9] = tp1[6];
				// apdu
				for (int i = 0; i < len; i++)
					ind[10 + i] = tp1[7 + i];
			}
			else {
				for (int i = 0; i < tp1.length - 1; i++)
					ind[2 + i] = tp1[i];
			}
			return ind;
		}

		private byte[] createBusmonInd(final byte[] tp1)
		{
			final int seq = busmonSequence;
			busmonSequence = (busmonSequence + 1) % 8;
			// provide 32 bit timestamp with 1 us precision
			final long timestamp = (System.nanoTime() / 1000) & 0xFFFFFFFFL;
			// NYI we could at least set frame error in status
			return CEMIBusMon.newWithSequenceNumber(seq, timestamp, true, tp1).toByteArray();
		}

		private void fireFrameReceived(final byte[] frame)
		{
			if (frame == null)
				return;
			logger.log(TRACE, "cEMI (length {0}): {1}", frame.length, DataUnitBuilder.toHex(frame, " "));
			try {
				final CEMI msg = CEMIFactory.create(frame, 0, frame.length);
				final FrameEvent fe = new FrameEvent(this, msg);
				listeners.fire(l -> l.frameReceived(fe));
			}
			catch (final KNXFormatException | RuntimeException e) {
				logger.log(ERROR, "invalid frame for cEMI: {0}", DataUnitBuilder.toHex(frame, " "), e);
			}
		}
	}
}
