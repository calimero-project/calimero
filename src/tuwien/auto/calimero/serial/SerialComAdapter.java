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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.IntStream;

import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.serial.spi.SerialCom;

/**
 * Adapter for serial communication using a Calimero library platform dependent library API.
 * <p>
 * The implementation of this API contains platform dependent code. It is used as a
 * fallback to enable serial communication on a RS-232 port in case the runtime default
 * access mechanism are not available or there is no protocol support.
 *
 * @author B. Malinowsky
 */
@SuppressWarnings("checkstyle:finalparameters")
public class SerialComAdapter implements SerialCom
{
	// ctrl identifiers
	static final int BAUDRATE = 1;
	static final int PARITY = 2;
	static final int DATABITS = 3;
	static final int STOPBITS = 4;
	static final int FLOWCTRL = 5;

	// flow control modes
	static final int FLOWCTRL_NONE = 0;
	static final int FLOWCTRL_CTSRTS = 1;

	// according DCB #defines in winbase.h
	static final int PARITY_NONE = 0;
	static final int PARITY_ODD = 1;
	static final int PARITY_EVEN = 2;
	static final int PARITY_MARK = 3;

	static final int ONE_STOPBIT = 1;
	static final int TWO_STOPBITS = 2;

	static final int AVAILABLE_INPUT_STATUS = 2;
	private static final int ERROR_STATUS = 1;
	private static final int LINE_STATUS = 3;

	// according EV #defines in winbase.h
	// CTS, DSR, RLSD and RING are voltage level change events

	// Any Character received
	private static final int EVENT_RXCHAR = 0x0001;
	// Received certain character
	private static final int EVENT_RXFLAG = 0x0002;
	// Transmit Queue Empty
	private static final int EVENT_TXEMPTY = 0x0004;
	// CTS changed state
	private static final int EVENT_CTS = 0x0008;
	// DSR changed state
	private static final int EVENT_DSR = 0x0010;
	// RLSD changed state
	private static final int EVENT_RLSD = 0x0020;
	// BREAK received
	private static final int EVENT_BREAK = 0x0040;
	// Line status error occurred
	private static final int EVENT_ERR = 0x0080;
	// Ring signal detected
	private static final int EVENT_RING = 0x0100;

	// error flags
	// #define CE_RXOVER 0x0001 // Receive Queue overflow
	// #define CE_OVERRUN 0x0002 // Receive Overrun Error
	// #define CE_RXPARITY 0x0004 // Receive Parity Error
	// #define CE_FRAME 0x0008 // Receive Framing error
	// #define CE_BREAK 0x0010 // Break Detected
	// #define CE_TXFULL 0x0100 // TX Queue is full
	// #define CE_MODE 0x8000 // Requested mode unsupported

	private static final boolean loaded;
	private static final int INVALID_HANDLE = -1;

	private long fd = INVALID_HANDLE;

	private final ReentrantLock lock = new ReentrantLock();
	private InputStream is;
	private OutputStream os;

	private final Logger logger;

	static final class Timeouts
	{
		final int readInterval;
		final int readTotalMultiplier;
		final int readTotalConstant;
		final int writeTotalMultiplier;
		final int writeTotalConstant;

		Timeouts(final int readInterval, final int readTotalMultiplier,
			final int readTotalConstant, final int writeTotalMultiplier,
			final int writeTotalConstant)
		{
			this.readInterval = readInterval;
			this.readTotalMultiplier = readTotalMultiplier;
			this.readTotalConstant = readTotalConstant;
			this.writeTotalMultiplier = writeTotalMultiplier;
			this.writeTotalConstant = writeTotalConstant;
		}

		@Override
		public String toString()
		{
			return "read " + readInterval + " read total " + readTotalMultiplier + " constant "
					+ readTotalConstant + " write total " + writeTotalMultiplier
					+ " write constant " + writeTotalConstant;
		}
	}

	static {
		boolean b = false;
		try {
			LogService.getLogger("calimero.serial").log(Level.TRACE, "check Java library path {0}", System.getProperty("java.library.path"));
			System.loadLibrary("serialcom");
			b = true;
		}
		catch (SecurityException | UnsatisfiedLinkError e) {
			LogService.getLogger("calimero.serial").log(Level.DEBUG, e.getMessage());
		}
		loaded = b;
	}

	public SerialComAdapter() {
		if (!loaded)
			throw new KnxRuntimeException("no serialcom library found");
		logger = LogService.getLogger("calimero.serial");
	}

	static native boolean portExists(String portId);

	@Override
	public List<String> portIdentifiers() {
		if (!loaded)
			return List.of();

		final List<String> ports = new ArrayList<>();
		LibraryAdapter.defaultPortPrefixes().forEach(p -> IntStream.range(0, 20).mapToObj(i -> p + i)
				.filter(SerialComAdapter::portExists).forEach(ports::add));
		return ports;
	}

	native int writeBytes(byte[] b, int off, int len) throws IOException;

	native int write(int b) throws IOException;

	native int readBytes(byte[] b, int off, int len) throws IOException;

	// return of -1 indicates timeout
	native int read() throws IOException;

	@Override
	public void setSerialPortParams(final int baudrate, final int databits, final StopBits stopbits, final Parity parity)
			throws IOException {
		setControl(BAUDRATE, baudrate);
		setControl(DATABITS, 8);
		setControl(STOPBITS, stopbits.value());
		setControl(PARITY, parity.value());
	}

	@Override
	public void setFlowControlMode(final FlowControl mode) throws IOException {
		setControl(FLOWCTRL, mode.value());
	}

	native void setTimeouts(Timeouts times) throws IOException;

	native Timeouts getTimeouts() throws IOException;

	@Override
	public int baudRate() throws IOException {
		return getControl(BAUDRATE);
	}

	// clear communication error and get device status
	native int getStatus(int type);

	native int setControl(int control, int newValue) throws IOException;

	native int getControl(int control) throws IOException;

	@Override
	public InputStream inputStream() {
		lock.lock();
		try {
			if (is == null)
				is = new PortInputStream(this);
			return is;
		}
		finally {
			lock.unlock();
		}
	}

	@Override
	public OutputStream outputStream() {
		lock.lock();
		try {
			if (os == null)
				os = new PortOutputStream(this);
			return os;
		}
		finally {
			lock.unlock();
		}
	}

	// any open input/output stream accessing this port becomes unusable
	@Override
	public final void close()
	{
		try {
			if (fd != INVALID_HANDLE)
				close0();
		}
		catch (final IOException e) {
			logger.log(Level.ERROR, "closing serial port", e);
		}
		fd = INVALID_HANDLE;
	}

	@Override
	public String toString() {
		if (fd == INVALID_HANDLE)
			return "closed";
		try {
			return "baudrate " + baudRate() + ", even parity, " + getControl(SerialComAdapter.DATABITS)
					+ " databits, " + getControl(SerialComAdapter.STOPBITS) + " stopbits, timeouts: " + getTimeouts();
		}
		catch (final IOException e) {
			return "invalid port setup";
		}
	}

	private native void setEvents(int eventMask, boolean enable) throws IOException;

	private native int waitEvent() throws IOException;

	@Override
	public native void open(String portId) throws IOException;

	private native void close0() throws IOException;
}
