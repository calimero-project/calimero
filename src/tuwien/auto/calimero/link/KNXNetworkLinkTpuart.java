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

import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.Collection;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.serial.KNXPortClosedException;
import tuwien.auto.calimero.serial.TpuartConnection;

/**
 * Implementation of the KNX network network link over TP-UART, using a {@link TpuartConnection}.
 * Once a link has been closed, it is not available for further communication, i.e. it can not be
 * reopened.
 *
 * @author B. Malinowsky
 * @see Connector
 */
public class KNXNetworkLinkTpuart extends AbstractLink<TpuartConnection>
{
	/**
	 * Creates a new network link for accessing the KNX network using the specified communication
	 * port identifier. The parameter {@code acknowledge} allows to configure KNX addresses
	 * that shall be acknowledged on the bus, e.g., the group address of a KNX datapoint this
	 * endpoint is answering to, or the individual address of an additional KNX device.
	 *
	 * @param portId name/identifier of the communication port
	 * @param settings KNX TP1 medium settings; if the settings contain a valid device address,
	 *        L-Data indications with that address will always be acknowledged on the TP1 bus
	 * @param acknowledge a (possibly empty) collection of KNX addresses this endpoint shall issue a
	 *        positive acknowledgement for, on receiving a valid TP1 frame with its destination
	 *        address being an element in {@code acknowledge}
	 * @throws KNXException on error establishing the TP-UART connection
	 */
	public KNXNetworkLinkTpuart(final String portId, final KNXMediumSettings settings,
		final Collection<? extends KNXAddress> acknowledge) throws KNXException
	{
		super(new TpuartConnection(portId, ensureDeviceAck(settings, acknowledge)),
				"tpuart:" + portId, settings);
		sendCEmiAsByteArray = true;
		conn.addConnectionListener(notifier);
	}

	/**
	 * Creates a new network link for accessing the KNX network using the supplied TP-UART
	 * connection.
	 *
	 * @param conn the connection, connection is in open state
	 * @param settings KNX TP1 medium settings
	 */
	protected KNXNetworkLinkTpuart(final TpuartConnection conn, final KNXMediumSettings settings)
	{
		super(conn, "tpuart:user", settings);
		if (settings.getMedium() != KNXMediumSettings.MEDIUM_TP1)
			throw new KNXIllegalArgumentException("TP-UART link supports only TP1 medium");
		sendCEmiAsByteArray = true;
		conn.addConnectionListener(notifier);
	}

	/**
	 * Adds an address to the list of addresses acknowledged on the bus.
	 *
	 * @param ack the address to acknowledge
	 */
	public final void addAddress(final KNXAddress ack)
	{
		conn.addAddress(ack);
	}

	/**
	 * Removes an address from the list of addresses acknowledged on the bus.
	 *
	 * @param ack the address to no further acknowledge
	 */
	public final void removeAddress(final KNXAddress ack)
	{
		conn.removeAddress(ack);
	}

	@Override
	protected void onSend(final KNXAddress dst, final byte[] msg, final boolean waitForCon)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		try {
			logger.log(Level.TRACE, () -> "send cEMI " + DataUnitBuilder.toHex(msg, " "));
			conn.send(msg, waitForCon);
		}
		catch (final InterruptedException | KNXPortClosedException e) {
			close();
			if (e instanceof InterruptedException)
				Thread.currentThread().interrupt();
			throw new KNXLinkClosedException(getName(), e);
		}
	}

	@Override
	protected void onSend(final CEMILData msg, final boolean waitForCon) {}

	// if possible, add this link to the list of addresses to acknowledge
	private static Collection<? extends KNXAddress> ensureDeviceAck(final KNXMediumSettings settings,
		final Collection<? extends KNXAddress> acknowledge)
	{
		if (settings.getMedium() != KNXMediumSettings.MEDIUM_TP1)
			throw new KNXIllegalArgumentException("TP-UART link supports only TP1 medium");
		// see if we have a valid device address assigned
		final IndividualAddress device = settings.getDeviceAddress();
		if (device.getDevice() == 0 || device.getDevice() == 0xff)
			return acknowledge;

		final ArrayList<KNXAddress> l = new ArrayList<>(acknowledge);
		l.add(device);
		return l;
	}
}
