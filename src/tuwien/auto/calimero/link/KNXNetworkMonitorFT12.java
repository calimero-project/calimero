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

package tuwien.auto.calimero.link;

import static java.lang.System.Logger.Level.INFO;

import java.util.function.Function;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.serial.FT12Connection;
import tuwien.auto.calimero.serial.KNXPortClosedException;

/**
 * Implementation of the KNX network monitor link based on the FT1.2 protocol, using a {@link FT12Connection}.
 * <p>
 * Once a monitor has been closed, it is not available for further link communication, i.e., it can't be reopened.
 *
 * @author B. Malinowsky
 */
public class KNXNetworkMonitorFT12 extends AbstractMonitor<FT12Connection>
{
	private final boolean cEMI;

	public static KNXNetworkMonitorFT12 newCemiMonitor(final String portId, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		return new KNXNetworkMonitorFT12(new FT12Connection(portId), settings, true);
	}

	/**
	 * Creates a new network monitor based on the FT1.2 protocol for accessing the KNX network.
	 * <p>
	 * The port identifier is used to choose the serial port for communication. These identifiers
	 * are usually device and platform specific.
	 *
	 * @param portID identifier of the serial communication port to use
	 * @param settings medium settings defining the specific KNX medium needed for decoding raw
	 *        frames received from the KNX network
	 * @throws KNXException on error creating FT1.2 connection or entering busmonitor mode
	 * @throws InterruptedException on thread interrupt creating the FT1.2 connection
	 */
	public KNXNetworkMonitorFT12(final String portID, final KNXMediumSettings settings)
			throws KNXException, InterruptedException
	{
		this(new FT12Connection(portID), settings);
	}

	/**
	 * Creates a new network monitor based on the FT1.2 protocol for accessing the KNX network.
	 * <p>
	 * The port number is used to choose the serial port for communication. It is mapped to the
	 * default port identifier using that number on the platform.
	 *
	 * @param portNumber port number of the serial communication port to use
	 * @param settings medium settings defining the specific KNX medium needed for decoding raw
	 *        frames received from the KNX network
	 * @throws KNXException on error creating FT1.2 connection or entering busmonitor mode
	 * @throws InterruptedException on thread interrupt creating the FT1.2 connection
	 */
	public KNXNetworkMonitorFT12(final int portNumber, final KNXMediumSettings settings)
			throws KNXException, InterruptedException
	{
		this(new FT12Connection(portNumber), settings);
	}

	/**
	 * Creates a new network monitor using the supplied FT1.2 connection for accessing the KNX
	 * network.
	 *
	 * @param conn an open FT12Connection, the link takes ownership
	 * @param settings medium settings defining the specific KNX medium needed for decoding raw
	 *        frames received from the KNX network
	 * @throws KNXException on error entering busmonitor mode
	 */
	protected KNXNetworkMonitorFT12(final FT12Connection conn, final KNXMediumSettings settings)
		throws KNXException
	{
		this(conn, settings, false);
	}

	/**
	 * Creates a new network monitor using the supplied FT1.2 connection with either cEMI or EMI2 format.
	 *
	 * @param conn an open FT12Connection, the link takes ownership
	 * @param settings medium settings defining the specific KNX medium needed for decoding raw
	 *        frames received from the KNX network
	 * @param cEMI {@code true} to use cEMI format, {@code false} to use EMI2 format
	 * @throws KNXException on error entering busmonitor mode
	 */
	protected KNXNetworkMonitorFT12(final FT12Connection conn, final KNXMediumSettings settings, final boolean cEMI)
			throws KNXException
	{
		super(conn, "monitor " + conn.getPortID(), settings);
		this.cEMI = cEMI;
		enterBusmonitor();
		logger.log(INFO, "in busmonitor mode - ready to receive");
		conn.addConnectionListener(notifier);
	}

	private void enterBusmonitor() throws KNXTimeoutException, KNXPortClosedException, KNXLinkClosedException {
		new BcuSwitcher<>(conn, logger, Function.identity()).enterBusmonitor(cEMI);
	}

	@Override
	protected void leaveBusmonitor()
	{
		try {
			new BcuSwitcher<>(conn, logger, Function.identity()).leaveBusmonitor(cEMI);
		}
		catch (KNXTimeoutException | KNXPortClosedException | KNXLinkClosedException e) {}
	}
}
