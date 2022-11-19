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

package tuwien.auto.calimero.knxnetip.servicetype;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger.Level;
import java.time.Duration;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;

/**
 * Represents a buffer overflow warning indication for KNX routing services.
 * <p>
 * The routing busy message informs about the situation when IP receive buffers have filled up to a
 * point where any subsequent received message may take at least 100 milliseconds to be forwarded to
 * the KNX subnetwork.<br>
 * If the incoming queue of a KNXnet/IP or KNX IP device exceeds a certain threshold of queued
 * messages that can be processed within a specific processing period, that device sends a
 * {@link RoutingBusy} indication. The indication provides the wait time required to empty the
 * incoming queue.<br>
 * The KNXnet/IP router or KNX IP device state and control information is supplied.
 * <p>
 * Objects of this type are immutable.
 *
 * @author B. Malinowsky
 */
public class RoutingBusy extends ServiceType
{
	private static final int typeSize = 6;

	private final int state;
	private final Duration waitTime;
	private final int ctrl;

	/**
	 * Creates a new routing busy indication out of a byte array.
	 *
	 * @param data byte array containing a lost message indication structure
	 * @param offset start offset of indication in {@code data}
	 * @throws KNXFormatException if buffer is too short for routing lost message indication or lost
	 *         message info has wrong size
	 */
	public RoutingBusy(final byte[] data, final int offset) throws KNXFormatException
	{
		super(KNXnetIPHeader.ROUTING_BUSY);
		if (data.length - offset < typeSize)
			throw new KNXFormatException("buffer too short for routing busy indication");
		final int size = data[offset] & 0xFF;
		if (size != typeSize)
			throw new KNXFormatException("wrong size for routing busy indication", size);
		state = data[offset + 1] & 0xFF;
		waitTime = Duration.ofMillis((data[offset + 2] & 0xFF) << 8 | (data[offset + 3] & 0xFF));
		ctrl = (data[offset + 4] & 0xFF) << 8 | (data[offset + 5] & 0xFF);
	}

	/**
	 * Creates a new routing busy indication.
	 *
	 * @param deviceState router device state, this router states are defined by the KNX property ID
	 *        69 in object type 11 of the KNX property definitions (with the state maintained by the
	 *        corresponding property value)
	 * @param waitTime time required to empty the affected receive queue,
	 *        {@code waitTime} shall be at least 20 ms and shall not exceed 100 ms
	 * @param control routing busy indication control field, default value is 0x0
	 */
	public RoutingBusy(final int deviceState, final Duration waitTime, final int control)
	{
		super(KNXnetIPHeader.ROUTING_BUSY);
		if (waitTime.toMillis() < 20 || waitTime.toMillis() > 100)
			throw new KNXIllegalArgumentException("wait time out of range [20..100] ms");
		if (deviceState < 0 || deviceState > 0xFF)
			throw new KNXIllegalArgumentException("device state field out of range [0..0xFF]");
		// bits 2 to 7 are reserved for now...
		if (deviceState > 0x03)
			ServiceType.logger.log(Level.INFO, "Bits 2..7 not supported in device state");
		state = deviceState;
		this.waitTime = waitTime;
		ctrl = control;
	}

	/**
	 * Returns the router device state, i.e., the value of the property defined by PID 69 in object
	 * type 11 of the KNX property definitions.
	 * <p>
	 *
	 * @return device state as unsigned byte
	 */
	public final int getDeviceState()
	{
		return state;
	}

	/**
	 * Returns whether the KNX network cannot be accessed, causing the routing busy indication.
	 * <p>
	 * The KNX fault mode is part of the device state.
	 *
	 * @return {@code true} on KNX access fault, {@code false} otherwise
	 * @see #getDeviceState()
	 */
	public final boolean isKnxFault()
	{
		return (state & 0x01) != 0;
	}

	/**
	 * Returns the time required to empty the affected receive queue.
	 * <p>
	 * If 1) {@link #getControl()} returns 0x0, or 2) {@link #getControl()} returns not 0x0 and the
	 * value is not interpreted by the receiving device, the receiving KNXnet/IP router or KNX IP
	 * device shall stop sending further routing indications for a time of {@link #waitTime()}.
	 * The following flow control mechanism applies:<br>
	 * The total timeout after which a KNX device is permitted to resume sending is calculated as
	 * {@code totalTime = waitTime() + rand(0..1) * N * 50 ms}.<br>
	 * The factor {@code N} is calculated as follows:
	 * <ul>
	 * <li>Increment {@code N} by one for each new routing busy indication received &ge; 10 ms
	 * have passed since the last routing busy indication.</li>
	 * <li>Decrement {@code N} by one every 5 ms after {@code t_slowduration} has elapsed.</li>
	 * <li>{@code t_slowduration} = N * 100 ms.</li>
	 * </ul>
	 *
	 * The wait time value used by the indicating device is also stored in the KNX property
	 * {@code ROUTING_BUSY_WAIT_TIME} with the {@code PID = 78}.
	 *
	 * @return time required to empty the affected receive queue, value shall be in
	 *         the range of {@code 20 ms ≤ time ≤ 100 ms}
	 */
	public final Duration waitTime() { return waitTime; }

	/**
	 * Returns the routing busy control field.
	 * <p>
	 * The default value is 0x00, requiring all KNXnet/IP and KNX/IP devices to act accordingly upon
	 * receiving this indication.
	 *
	 * @return the 2 byte routing busy control field as int
	 */
	public final int getControl()
	{
		return ctrl;
	}

	@Override
	public String toString() {
		return super.toString() + " 0x" + Integer.toHexString(ctrl) + (isKnxFault() ? " KNX network fault" : "")
				+ ", wait " + waitTime.toMillis() + " ms";
	}

	@Override
	int getStructLength()
	{
		return typeSize;
	}

	@Override
	byte[] toByteArray(final ByteArrayOutputStream os)
	{
		os.write(typeSize);
		os.write(state);
		os.write((int) (waitTime.toMillis() >> 8));
		os.write((int) waitTime.toMillis());
		os.write(ctrl >> 8);
		os.write(ctrl);
		return os.toByteArray();
	}
}
