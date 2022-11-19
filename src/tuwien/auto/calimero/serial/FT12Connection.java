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

package tuwien.auto.calimero.serial;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.System.Logger;
import java.time.Duration;
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
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXListener;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.internal.Executor;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.serial.spi.SerialCom;
import tuwien.auto.calimero.serial.spi.SerialCom.Parity;
import tuwien.auto.calimero.serial.spi.SerialCom.StopBits;

/**
 * Provides a connection based on the FT1.2 protocol for communication with a BCU2 device.
 * <p>
 * It supports establishing a connection over serial port identifiers recognized and
 * supported by the underlying operating system.
 * <p>
 * Access to log event information:<br>
 * See the corresponding constructors of this class for how to get the associated log
 * service.
 *
 * @author B. Malinowsky
 */
public class FT12Connection implements Connection<byte[]>
{
	/**
	 * State of communication: in idle state, no error, ready to send.
	 */
	public static final int OK = 0;

	/**
	 * State of communication: in closed state, no send possible.
	 */
	public static final int CLOSED = 1;

	/**
	 * Status code of communication: waiting for acknowledge after send, no error, not
	 * ready to send.
	 */
	public static final int ACK_PENDING = 2;

	/**
	 * Status code of communication: waiting for .con after send, no error, not ready to send.
	 */
	public static final int CON_PENDING = 3;

	// default used baud rate for BAU
	private static final int DEFAULT_BAUDRATE = 19200;

	// primary station control field
	static final int DIR_FROM_BAU = 0x80;
	static final int INITIATOR = 0x40;
	private static final int FRAMECOUNT_BIT = 0x20;

	// frame count valid is always set on sending user data
	private static final int FRAMECOUNT_VALID = 0x10;
	static final int ACK = 0xE5;
	// primary station service codes
	private static final int RESET = 0x00;
	private static final int USER_DATA = 0x03;
	private static final int REQ_STATUS = 0x09;
	// secondary station control field (used only for response to REQ_STATUS)
	// reserved bit, always 0
	// private static final int RESERVED = 0x20;
	// secondary station service codes
	// private static final int CONFIRM_ACK = 0x00;
	// private static final int CONFIRM_NACK = 0x01;
	// private static final int RESPONSE_STATUS = 0x0B;

	// timeout for end of frame exchange [Bits]
	private static final int EXCHANGE_TIMEOUT = 512;
	// limit for retransmissions of discarded frames
	private static final int REPEAT_LIMIT = 3;
	// maximum time between two frame characters, minimum time to indicate error [Bits]
	private static final int IDLE_TIMEOUT = 33;

	// frame delimiter characters
	static final int START = 0x68;
	static final int START_FIXED = 0x10;
	private static final int END = 0x16;

	private final Logger logger;

	// adapter for the used serial I/O connection:
	// - for Calimero 2 native I/O, SerialComAdapter is used
	// - with rx/tx available, RxtxAdapter is used
	// - or some external serial I/O library adapter
	private final SerialCom adapter;

	private final String port;
	private final int exchangeTimeout;
	private final boolean cemi;
	private final InputStream is;
	private final OutputStream os;
	private volatile int state = CLOSED;

	private final Receiver receiver;
	private final ReentrantLock sendLock = new ReentrantLock(true);
	private final Condition readyToSend = sendLock.newCondition();
	private final Condition ack = sendLock.newCondition();
	private final Condition con = sendLock.newCondition();

	private volatile KNXAddress keepForCon;
	private static final IndividualAddress NoLDataAddress = new IndividualAddress(0xffff);

	private volatile int sendFrameCount;
	private volatile int rcvFrameCount;

	private final EventListeners<KNXListener> listeners;

	/**
	 * Creates a new connection to a BCU2 using the FT1.2 protocol.
	 * <p>
	 * If the port to use can not be told just by the number, use
	 * {@link FT12Connection#FT12Connection(String)}.<br>
	 * The baud rate is set to 19200.<br>
	 * The associated log service to which the created instance will output logging events
	 * is named "calimero.serial.ft12:{@code portId}", with {@code portId} being the
	 * port identifier created from {@code portNumber}.
	 *
	 * @param portNumber port number of the serial communication port to use; mapped to
	 *        the default port identifier using this number (device and platform specific)
	 * @throws KNXException on port not found or access error, initializing port settings
	 *         failed, if reset of BCU2 failed
	 * @throws InterruptedException on interrupted thread while creating the FT1.2 connection
	 */
	public FT12Connection(final int portNumber) throws KNXException, InterruptedException
	{
		this(LibraryAdapter.defaultPortPrefixes().get(0) + portNumber, DEFAULT_BAUDRATE, false);
	}

	/**
	 * Creates a new connection to a BCU2 using the FT1.2 protocol.
	 * <p>
	 * The baud rate is set to 19200.<br>
	 * The associated log service to which the created instance will output logging events
	 * is named "calimero.serial.ft12:{@code portId}", with {@code portId} being the supplied
	 * port identifier.
	 *
	 * @param portId port identifier of the serial communication port to use
	 * @throws KNXException on port not found or access error, initializing port settings
	 *         failed, if reset of BCU2 failed
	 * @throws InterruptedException on interrupted thread while creating the FT1.2 connection
	 */
	public FT12Connection(final String portId) throws KNXException, InterruptedException
	{
		this(portId, DEFAULT_BAUDRATE, false);
	}

	/**
	 * Creates a new connection to a BCU2 using the FT1.2 protocol, and set the baud rate
	 * for communication.
	 * <p>
	 * If the requested baud rate is not supported, it may get substituted with a valid
	 * baud rate by default.<br>
	 * For access to the log service, see {@link #FT12Connection(String)}.
	 *
	 * @param portId port identifier of the serial communication port to use
	 * @param baudrate baud rate to use for communication, 0 &lt; baud rate
	 * @throws KNXException on port not found or access error, initializing port settings
	 *         failed, if reset of BCU2 failed
	 * @throws InterruptedException on interrupted thread while creating the FT1.2 connection
	 */
	public FT12Connection(final String portId, final int baudrate) throws KNXException, InterruptedException
	{
		this(portId, baudrate, false);
	}

	/**
	 * Creates a new connection to a BCU2 using the FT1.2 protocol with specified baud rate and EMI setting
	 * for communication.
	 * <p>
	 * If the requested baud rate is not supported, it may get substituted with a valid
	 * baud rate by default.<br>
	 * For access to the log service, see {@link #FT12Connection(String)}.
	 *
	 * @param portId port identifier of the serial communication port to use
	 * @param baudrate baud rate to use for communication, 0 &lt; baud rate
	 * @param cemi {@code true} if connection uses cEMI frames, {@code false} otherwise
	 * @throws KNXException on port not found or access error, initializing port settings
	 *         failed, if reset of BCU2 failed
	 * @throws InterruptedException on interrupted thread while creating the FT1.2 connection
	 */
	public FT12Connection(final String portId, final int baudrate, final boolean cemi)
			throws KNXException, InterruptedException {
		this(LibraryAdapter.open(LogService.getLogger("calimero.serial.ft12:" + portId), portId, baudrate,
				idleTimeout(baudrate)), portId, cemi);
	}

	protected FT12Connection(final SerialCom connection, final String portId, final boolean cemi)
			throws KNXException, InterruptedException {
		logger = LogService.getLogger("calimero.serial.ft12:" + portId);
		listeners = new EventListeners<>(logger);
		listeners.registerEventType(ConnectionStatus.class);

		adapter = connection;
		port = portId;
		try {
			exchangeTimeout = exchangeTimeout(adapter.baudRate());
		}
		catch (final IOException e) {
			throw new KNXException("calculating exchange timeout", e);
		}
		this.cemi = cemi;
		is = adapter.inputStream();
		os = adapter.outputStream();
		receiver = new Receiver();
		Executor.execute(receiver, "Calimero FT1.2 receiver");
		state = OK;

		reset();
	}

	/**
	 * Attempts to gets the available serial communication ports on the host.
	 * <p>
	 * If Calimero has access to serial ports, the lowest 20
	 * port numbers of each of the default system name prefixes are checked if present.<br>
	 * The empty array is returned if no ports are discovered.
	 *
	 * @return array of strings with found port identifiers
	 */
	public static String[] getPortIdentifiers()
	{
		return LibraryAdapter.getPortIdentifiers().toArray(String[]::new);
	}

	/**
	 * Adds the specified event listener {@code l} to receive events from this
	 * connection.
	 * <p>
	 * If {@code l} was already added as listener, no action is performed.
	 *
	 * @param l the listener to add
	 */
	@Override
	public void addConnectionListener(final KNXListener l)
	{
		listeners.add(l);
	}

	/**
	 * Removes the specified event listener {@code l}, so it does no longer receive
	 * events from this connection.
	 * <p>
	 * If {@code l} was not added in the first place, no action is performed.
	 *
	 * @param l the listener to remove
	 */
	@Override
	public void removeConnectionListener(final KNXListener l)
	{
		listeners.remove(l);
	}

	@Override
	public String name()
	{
		return port;
	}

	/**
	 * Returns the port identifier in use for this connection.
	 * <p>
	 * After the connection is closed, the returned identifier will always be the empty
	 * string.
	 *
	 * @return port identifier as string, or empty string
	 */
	public final String getPortID()
	{
		return state == CLOSED ? "" : port;
	}

	/**
	 * Sets a new baud rate for this connection.
	 *
	 * @param baud requested baud rate [bit/s], 0 &lt; baud rate
	 * @throws IOException on error setting the baudrate
	 */
	public void setBaudrate(final int baud) throws IOException
	{
		adapter.setSerialPortParams(baud, 8, StopBits.One, Parity.Even);
	}

	/**
	 * Returns the currently used baud rate.
	 * <p>
	 * After closing the connection, the returned baud rate is 0 by default.
	 *
	 * @return baud rate in Bit/s
	 * @throws IOException
	 */
	final int getBaudRate() throws IOException
	{
		return adapter.baudRate();
	}

	/**
	 * Returns information about the current FT1.2 communication state.
	 *
	 * @return state enumeration
	 */
	public final int getState()
	{
		return state;
	}

	@Override
	public void send(final byte[] frame, final BlockingMode blockingMode)
			throws KNXTimeoutException, KNXPortClosedException, InterruptedException {
		send(frame, blockingMode != BlockingMode.NonBlocking);
	}

	/**
	 * Sends an EMI frame to the BCU2 connected with this endpoint.
	 * <p>
	 * In blocking mode, all necessary retransmissions of the sent frame will be done
	 * automatically according to the protocol specification (i.e., in case of timeout).<br>
	 * If a communication failure occurs on the port, {@link #close()} is called. A send
	 * timeout does not lead to closing of this connection.<br>
	 * In blocking send mode, on successfully receiving a confirmation, all listeners are
	 * guaranteed to get notified before this method returns. The communication state (see
	 * {@link #getState()}) is reset to {@link #OK} when the notification completed, so to
	 * prevent another send call from a listener.
	 *
	 * @param frame EMI message to send, length of frame &lt; 256 bytes
	 * @param blocking {@code true} to block for confirmation (ACK),
	 *        {@code false} to immediately return after send
	 * @throws KNXAckTimeoutException in {@code blocking} mode, if a timeout
	 *         regarding the frame acknowledgment message was encountered
	 * @throws KNXTimeoutException in {@code blocking} mode, if a timeout
	 *         regarding the frame confirmation message was encountered
	 * @throws KNXPortClosedException if no communication was established in the first
	 *         place or communication was closed
	 * @throws InterruptedException on thread interruption during sending the frame; the
	 *         connection is not closed because of the interruption
	 */
	public void send(final byte[] frame, final boolean blocking)
		throws KNXTimeoutException, KNXPortClosedException, InterruptedException
	{
		sendLock.lockInterruptibly();
		try {
			while (state != OK) {
				if (state == CLOSED)
					throw new KNXPortClosedException("waiting to send", port);
				readyToSend.await();
			}

			boolean ack = false;
			boolean con = false;
			for (int i = 0; i <= REPEAT_LIMIT; ++i) {
				logger.log(TRACE, "sending FT1.2 frame, {0}blocking, attempt {2}", (blocking ? "" : "non-"), (i + 1));

				// setup for L-Data.con
				final boolean isLDataReq = (frame[0] & 0xff) == CEMILData.MC_LDATA_REQ;
				keepForCon = isLDataReq ? ldataDestination(frame) : NoLDataAddress;

				sendData(frame);
				if (!blocking) {
					ack = true;
					con = true;
					break;
				}
				if (waitForAck()) {
					ack = true;
					if (!isLDataReq || waitForCon())
						con = true;
					break;
				}
			}
			sendFrameCount ^= FRAMECOUNT_BIT;
			if (!ack)
				throw new KNXAckTimeoutException("no acknowledge reply received");
			if (!con)
				throw new KNXTimeoutException("no confirmation reply received for " + keepForCon);
		}
		catch (final InterruptedIOException e) {
			throw new InterruptedException(e.getMessage());
		}
		catch (final IOException e) {
			close(false, e.getMessage());
			throw new KNXPortClosedException(e.getMessage(), port, e);
		}
		finally {
			if (state == ACK_PENDING || state == CON_PENDING)
				state = OK;
			keepForCon = NoLDataAddress;
			readyToSend.signal();
			sendLock.unlock();
		}
	}

	/**
	 * Ends communication with the BCU2 as specified by the FT1.2 protocol.
	 * <p>
	 * The BCU is always switched back into normal mode.<br>
	 * All registered event listeners get notified. The close event is the last event the
	 * listeners receive.
	 * If this connection endpoint is already closed, no action is performed.
	 */
	@Override
	public void close()
	{
		close(true, "client request");
	}

	private void close(final boolean user, final String reason)
	{
		if (state == CLOSED)
			return;
		logger.log(INFO, "close serial port " + port + " - " + reason);

		sendLock.lock();
		try {
			state = CLOSED;
			ack.signalAll();
			con.signalAll();
			readyToSend.signalAll();
		}
		finally {
			sendLock.unlock();
		}

		if (receiver != null)
			receiver.quit();

		try {
			is.close();
			os.close();
			adapter.close();
		}
		catch (final Exception e) {
			logger.log(WARNING, "failed to close all serial I/O resources", e);
		}

		fireConnectionClosed(user, reason);
	}

	private void reset() throws InterruptedException, KNXPortClosedException, KNXAckTimeoutException {
		sendLock.lockInterruptibly();
		try {
			sendReset();
		}
		catch (final KNXAckTimeoutException e) {
			close(false, "acknowledgment timeout on sending reset");
			throw e;
		}
		finally {
			sendLock.unlock();
		}
	}

	private void sendReset() throws KNXPortClosedException, KNXAckTimeoutException
	{
		try {
			final byte[] reset = new byte[] { START_FIXED, INITIATOR | RESET, INITIATOR | RESET, END };
			for (int i = 0; i <= REPEAT_LIMIT; ++i) {
				logger.log(TRACE, "send reset to BCU");
				state = ACK_PENDING;
				os.write(reset);
				os.flush();
				if (waitForAck(Duration.ofMillis(150))) {
					state = OK;
					return;
				}
			}
			throw new KNXAckTimeoutException("resetting BCU failed (no acknowledge reply received)");
		}
		catch (final InterruptedException e) {
			close(true, "send reset interruption, " + e.getMessage());
			Thread.currentThread().interrupt();
			throw new KNXPortClosedException("interrupted during send reset", port);
		}
		catch (final IOException e) {
			close(false, e.getMessage());
			throw new KNXPortClosedException("I/O error", port, e);
		}
		finally {
			sendFrameCount = FRAMECOUNT_BIT;
			rcvFrameCount = FRAMECOUNT_BIT;
		}
	}

	private void sendData(final byte[] data) throws IOException, KNXPortClosedException
	{
		if (data.length > 255)
			throw new KNXIllegalArgumentException("data length > 255 bytes");
		if (state == CLOSED)
			throw new KNXPortClosedException("connection closed", port);
		final byte[] buf = new byte[data.length + 7];
		int i = 0;
		buf[i++] = START;
		buf[i++] = (byte) (data.length + 1);
		buf[i++] = (byte) (data.length + 1);
		buf[i++] = START;
		buf[i++] = (byte) (INITIATOR | sendFrameCount | FRAMECOUNT_VALID | USER_DATA);
		for (int k = 0; k < data.length; ++k)
			buf[i++] = data[k];
		buf[i++] = checksum(buf, 4, data.length + 1);
		buf[i++] = END;

		state = ACK_PENDING;
		os.write(buf);
		os.flush();
	}

	private void sendAck() throws IOException
	{
		os.write(ACK);
		os.flush();
	}

	// pre: sendLock is held
	private boolean waitForAck() throws InterruptedException {
		return waitForAck(Duration.ofMillis(exchangeTimeout));
	}

	// pre: sendLock is held
	private boolean waitForAck(final Duration timeout) throws InterruptedException {
		long remaining = timeout.toNanos();
		while (state == ACK_PENDING && remaining > 0)
			remaining = ack.awaitNanos(remaining);
		return remaining > 0;
	}

	// pre: sendLock is held
	private boolean waitForCon() throws InterruptedException {
		long remaining = Duration.ofMillis(300).toNanos();
		while (state == CON_PENDING && remaining > 0)
			remaining = con.awaitNanos(remaining);
		return remaining > 0;
	}

	private void fireConnectionClosed(final boolean user, final String reason)
	{
		final int initiator = user ? CloseEvent.USER_REQUEST : CloseEvent.INTERNAL;
		final CloseEvent ce = new CloseEvent(this, initiator, reason);
		listeners.fire(l -> l.connectionClosed(ce));
	}

	private static int exchangeTimeout(final int baudrate) {
		// with some serial driver/BCU/OS combinations, the calculated
		// timeouts are just too short, so add some milliseconds just as it fits
		// this little extra time usually doesn't hurt
		final int xTolerance = 5;
		return Math.round(1000f * EXCHANGE_TIMEOUT / baudrate) + xTolerance;
	}

	private static int idleTimeout(final int baudrate) {
		// with some serial driver/BCU/OS combinations, the calculated
		// timeouts are just too short, so add some milliseconds just as it fits
		// this little extra time usually doesn't hurt
		final int iTolerance = 15;
		return Math.round(1000f * IDLE_TIMEOUT / baudrate) + iTolerance;
	}

	private static byte checksum(final byte[] data, final int offset, final int length)
	{
		byte chk = 0;
		for (int i = 0; i < length; ++i)
			chk += data[offset + i];
		return chk;
	}

	private KNXAddress ldataDestination(final byte[] ldata) {
		if (ldata.length >= 8) {
			final int dstOffset = cemi ? 6 : 4;
			final int addressTypeOffset = cemi ? 3 : 6;

			final int addr = (ldata[dstOffset] & 0xff) << 8 | ldata[dstOffset + 1] & 0xff;
			final boolean group = (ldata[addressTypeOffset] & 0x80) == 0x80;
			return group ? new GroupAddress(addr) : new IndividualAddress(addr);
		}
		return NoLDataAddress;
	}

	private final class Receiver implements Runnable
	{
		private volatile boolean quit;
		private volatile Thread thread;

		private int lastChecksum;

		@Override
		public void run()
		{
			thread = Thread.currentThread();
			try {
				while (!quit) {
					final int c = is.read();
					if (c > -1) {
						if (c == ACK)
							signalAck();
						else if (c == START)
							readFrame();
						else if (c == START_FIXED)
							readShortFrame();
						else
							logger.log(TRACE, "received unexpected start byte 0x" + Integer.toHexString(c) + " - ignored");
					}
				}
			}
			catch (final IOException | InterruptedException e) {
				if (!quit) {
					logger.log(WARNING, "I/O error in FT1.2 receiver", e);
					close(false, "receiver communication failure");
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

		private boolean readShortFrame() throws IOException
		{
			final byte[] buf = new byte[3];
			if (is.read(buf) == 3 && buf[0] == buf[1] && (buf[2] & 0xff) == END) {
				// for our purposes (reset and status), FRAMECOUNT_VALID is never set
				if ((buf[0] & 0x30) == 0) {
					sendAck();
					final int fc = buf[0] & 0x0f;
					logger.log(TRACE, "received " + (fc == RESET ? "reset" : fc == REQ_STATUS
							? "status" : "unknown function code "));
					if (fc == RESET) {
						sendFrameCount = FRAMECOUNT_BIT;
						rcvFrameCount = FRAMECOUNT_BIT;
						notifyReset();
					}

					return true;
				}
			}
			return false;
		}

		private void notifyReset() {
			listeners.dispatchCustomEvent(ConnectionStatus.Reset);
		}

		private boolean readFrame() throws IOException, InterruptedException
		{
			final byte[] header = is.readNBytes(3);
			// check end of stream
			if (header.length != 3)
				return false;

			final int len = header[0] & 0xff;
			final int lenCheck = header[1] & 0xff;
			if (len != lenCheck) {
				logger.log(DEBUG, "invalid frame header, length fields mismatch {0} != {1}", len, lenCheck);
				return false;
			}
			final int startMarker = header[2] & 0xff;
			if (startMarker != START) {
				logger.log(DEBUG, "invalid frame header, expected START: {0}", Integer.toHexString(startMarker));
				return false;
			}

			final int total = len + 2;
			// read rest of frame, check header, ctrl, and end tag
			final byte[] buf = is.readNBytes(total);
			final int read = buf.length;
			if (read == total && (buf[len + 1] & 0xff) == END) {
				final byte chk = buf[buf.length - 2];
				if (!checkCtrlField(buf[0] & 0xff, chk))
					return false;

				if (checksum(buf, 0, len) != chk)
					logger.log(WARNING, "invalid checksum in frame " + DataUnitBuilder.toHex(buf, " "));
				else {
					sendAck();
					lastChecksum = chk;
					rcvFrameCount ^= FRAMECOUNT_BIT;
					final byte[] ldata = new byte[len - 1];
					for (int i = 0; i < ldata.length; ++i)
						ldata[i] = buf[1 + i];

					fireFrameReceived(ldata);

					checkLDataCon(ldata);
					return true;
				}
			}
			else
				logger.log(WARNING, "invalid frame, discarded " + read + " bytes: " + DataUnitBuilder.toHex(buf, " "));
			return false;
		}

		private boolean checkCtrlField(final int c, final byte chk)
		{
			if ((c & (DIR_FROM_BAU | INITIATOR)) != (DIR_FROM_BAU | INITIATOR)) {
				logger.log(WARNING, "unexpected ctrl field 0x" + Integer.toHexString(c));
				return false;
			}
			if ((c & FRAMECOUNT_VALID) == FRAMECOUNT_VALID) {
				if ((c & FRAMECOUNT_BIT) != rcvFrameCount) {
					// ignore repeated frame
					if (chk == lastChecksum) {
						logger.log(TRACE, "framecount and checksum indicate a repeated frame - ignored");
						return false;
					}
					// protocol discrepancy (Merten Instabus coupler)
					logger.log(WARNING, "toggle frame count bit");
					rcvFrameCount ^= FRAMECOUNT_BIT;
				}
			}
			if ((c & 0x0f) == USER_DATA && (c & FRAMECOUNT_VALID) == 0)
				return false;
			return true;
		}

		private void checkLDataCon(final byte[] ldata) throws InterruptedException {
			final int emi1LDataCon = 0x4e;
			final int svc = ldata[0] & 0xff;
			final boolean isLDataCon = svc == CEMILData.MC_LDATA_CON || svc == emi1LDataCon;
//			final int ctrl1Offset = cemi ? 2 : 1;
//			final boolean posCon = (ldata[ctrl1Offset] & 0x01) == 0;
			if (isLDataCon) {
				final var dst = ldataDestination(ldata);
				if (dst.equals(keepForCon))
					signalCon();
			}
		}

		private void signalAck() throws InterruptedException {
			sendLock.lockInterruptibly();
			try {
				if (state == ACK_PENDING) {
					state = CON_PENDING;
					ack.signal();
				}
			}
			finally {
				sendLock.unlock();
			}
		}

		private void signalCon() throws InterruptedException {
			sendLock.lockInterruptibly();
			try {
				if (state == CON_PENDING) {
					state = OK;
					con.signal();
				}
			}
			finally {
				sendLock.unlock();
			}
		}

		/**
		 * Fires a frame received event ({@link KNXListener#frameReceived(FrameEvent)})
		 * for the supplied EMI2 {@code frame}.
		 *
		 * @param frame the EMI2 L-data frame to generate the event for
		 */
		private void fireFrameReceived(final byte[] frame)
		{
			final FrameEvent fe = new FrameEvent(this, frame);
			listeners.fire(l -> l.frameReceived(fe));
		}
	}
}
