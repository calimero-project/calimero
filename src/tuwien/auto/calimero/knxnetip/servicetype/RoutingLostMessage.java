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

package tuwien.auto.calimero.knxnetip.servicetype;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger.Level;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;

/**
 * Represents an indication for lost routing messages for routing services.
 * <p>
 * The routing lost message is used to inform about the fact, that routing messages were
 * lost due to an overflow in the LAN-to-KNX queue, i.e., a router receives more IP
 * packets than it is able to deliver to the KNX network.<br>
 * Additionally, the router device state is supplied.
 * <p>
 * Objects of this type are immutable.
 *
 * @author B. Malinowsky
 */
public class RoutingLostMessage extends ServiceType
{
	private final int lost;
	private final int state;

	/**
	 * Creates a new routing lost message indication out of a byte array.
	 * <p>
	 *
	 * @param data byte array containing a lost message indication structure
	 * @param offset start offset of indication in {@code data}
	 * @throws KNXFormatException if buffer is too short for routing lost message
	 *         indication or lost message info has wrong size
	 */
	public RoutingLostMessage(final byte[] data, final int offset) throws KNXFormatException
	{
		super(KNXnetIPHeader.ROUTING_LOST_MSG);
		if (data.length - offset < 4)
			throw new KNXFormatException("buffer too short for lost messages info");
		final int size = data[offset] & 0xFF;
		if (size != 4)
			throw new KNXFormatException("wrong size for lost messages info", size);
		state = data[offset + 1] & 0xFF;
		lost = (data[offset + 2] & 0xFF) << 8 | (data[offset + 3] & 0xFF);
	}

	/**
	 * Creates a new routing lost message indication.
	 * <p>
	 *
	 * @param lostMessages number of KNXnet/IP routing messages lost
	 * @param deviceState router device state, this router states are defined by the KNX
	 *        property ID 69 in object type 11 of the KNX property definitions (with the
	 *        state maintained by the corresponding property value)
	 */
	public RoutingLostMessage(final int lostMessages, final int deviceState)
	{
		super(KNXnetIPHeader.ROUTING_LOST_MSG);
		if (lostMessages < 0 || lostMessages > 0xFFFF)
			throw new KNXIllegalArgumentException("lost message count out of range [0..0xFFFF]");
		if (deviceState < 0 || deviceState > 0xFF)
			throw new KNXIllegalArgumentException("device state field out of range [0..0xFF]");
		// bits 2 to 7 are reserved for now...
		if (deviceState > 0x03)
			ServiceType.logger.log(Level.INFO, "Bits 2..7 not supported in device state");
		lost = lostMessages;
		state = deviceState;
	}

	/**
	 * The number of lost KNXnet/IP routing messages.
	 * <p>
	 *
	 * @return lost messages as unsigned 16 bit value
	 */
	public final int getLostMessages()
	{
		return lost;
	}

	/**
	 * Returns the router device state, i.e., the value of the property defined by PID 69
	 * in object type 11 of the KNX property definitions.
	 * <p>
	 *
	 * @return device state as unsigned byte
	 */
	public final int getDeviceState()
	{
		return state;
	}

	/**
	 * Returns whether the KNX network cannot be accessed, causing the message loss.
	 * <p>
	 * The KNX fault mode is part of the device state.
	 *
	 * @return {@code true} on KNX access fault, {@code false} otherwise
	 * @see #getDeviceState()
	 */
	public final boolean isKNXFault()
	{
		return (state & 0x01) != 0;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.knxnetip.servicetype.ServiceType#getStructLength()
	 */
	@Override
	int getStructLength()
	{
		return 4;
	}

	/* (non-Javadoc)
	 * @see tuwien.auto.calimero.knxnetip.servicetype.ServiceType#toByteArray
	 * (java.io.ByteArrayOutputStream)
	 */
	@Override
	byte[] toByteArray(final ByteArrayOutputStream os)
	{
		os.write(4);
		os.write(state);
		os.write(lost >> 8);
		os.write(lost);
		return os.toByteArray();
	}
}
