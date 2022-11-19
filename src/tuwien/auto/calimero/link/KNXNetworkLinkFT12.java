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

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.util.function.Function;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXListener;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.internal.Executor;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.serial.ConnectionEvent;
import tuwien.auto.calimero.serial.ConnectionStatus;
import tuwien.auto.calimero.serial.FT12Connection;
import tuwien.auto.calimero.serial.KNXPortClosedException;

/**
 * Implementation of the KNX network network link based on the FT1.2 protocol, using a {@link FT12Connection}.
 *
 * @author B. Malinowsky
 */
public class KNXNetworkLinkFT12 extends AbstractLink<FT12Connection>
{
	public static KNXNetworkLinkFT12 newCemiLink(final String portId, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		return new KNXNetworkLinkFT12(new FT12Connection(portId, 19200, true), settings, true);
	}

	/**
	 * Creates a new network link based on the FT1.2 protocol for accessing the KNX network.
	 * <p>
	 * The port identifier is used to choose the serial port for communication. These identifiers
	 * are usually device and platform specific.
	 *
	 * @param portID identifier of the serial communication port to use
	 * @param settings medium settings defining device and medium specifics needed for communication
	 * @throws KNXException on error creating FT1.2 connection, or timeout switching to link layer mode
	 * @throws InterruptedException on thread interrupt creating the FT1.2 connection
	 */
	public KNXNetworkLinkFT12(final String portID, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		this(new FT12Connection(portID), settings);
	}

	/**
	 * Creates a new network link based on the FT1.2 protocol for accessing the KNX network.
	 * <p>
	 * The port number is used to choose the serial port for communication. It is mapped to the
	 * default port identifier using that number on the platform.
	 *
	 * @param portNumber port number of the serial communication port to use
	 * @param settings medium settings defining device and medium specifics needed for communication
	 * @throws KNXException on error creating FT1.2 connection, or timeout switching to link layer mode
	 * @throws InterruptedException on thread interrupt creating the FT1.2 connection
	 */
	public KNXNetworkLinkFT12(final int portNumber, final KNXMediumSettings settings)
			throws KNXException, InterruptedException {
		this(new FT12Connection(portNumber), settings);
	}

	/**
	 * Creates a new network link to a KNX network based on the supplied FT1.2 protocol connection.
	 *
	 * @param c a FT1.2 protocol connection in open state
	 * @param settings medium settings defining device and medium specifics needed for communication
	 * @throws KNXException on error, timeout, or interrupt while switching to link layer mode
	 */
	protected KNXNetworkLinkFT12(final FT12Connection c, final KNXMediumSettings settings) throws KNXException
	{
		this(c, settings, false);
	}

	/**
	 * Creates a new KNX network link using the supplied FT1.2 protocol connection with either cEMI or EMI2 format.
	 *
	 * @param c a FT1.2 protocol connection in open state
	 * @param settings medium settings defining device and medium specifics needed for communication
	 * @param cEMI {@code true} to use cEMI format, {@code false} to use EMI2 format
	 * @throws KNXException on error, timeout, or interrupt while switching to link layer mode
	 */
	protected KNXNetworkLinkFT12(final FT12Connection c, final KNXMediumSettings settings, final boolean cEMI)
			throws KNXException {
		super(c, c.getPortID(), settings);
		this.cEMI = cEMI;
		sendCEmiAsByteArray = true;
		linkLayerMode();
		conn.addConnectionListener(notifier);
		conn.addConnectionListener(new KNXListener() {
			@Override
			public void frameReceived(final FrameEvent e) {}

			@ConnectionEvent
			void connectionStatus(final ConnectionStatus status) {
				if (status == ConnectionStatus.Reset)
					connectionReset();
			}
		});
	}

	@Override
	protected void onSend(final KNXAddress dst, final byte[] msg, final boolean waitForCon)
		throws KNXTimeoutException, KNXLinkClosedException
	{
		try {
			logger.log(DEBUG, "send message to {0}{1}", dst, (waitForCon ? ", wait for ack" : ""));
			logger.log(TRACE, () -> "EMI " + DataUnitBuilder.toHex(msg, " "));
			conn.send(msg, waitForCon);
			logger.log(TRACE, "send to {0} succeeded", dst);
		}
		catch (KNXPortClosedException | InterruptedException e) {
			logger.log(ERROR, "send error, closing link", e);
			close();
			if (e instanceof InterruptedException)
				Thread.currentThread().interrupt();
			throw new KNXLinkClosedException("link closed, " + e.getMessage());
		}
	}

	@Override
	protected void onSend(final CEMILData msg, final boolean waitForCon) {}

	@Override
	protected void onClose()
	{
		try {
			normalMode();
		}
		catch (final Exception e) {
			logger.log(WARNING, "could not switch BCU back to normal mode", e);
		}
	}

	private void connectionReset() {
		// don't run this in notification thread!
		final Runnable modeSetter = () -> {
			try {
				if (baosMode)
					baosMode(true);
				else
					linkLayerMode();
			}
			catch (KNXException | InterruptedException e) {
				close();
			}
		};
		Executor.execute(modeSetter, "FT1.2 connection reset mode switcher");
	}

	private void linkLayerMode() throws KNXException {
		new BcuSwitcher<>(conn, logger, Function.identity()).linkLayerMode(cEMI);
	}

	private void normalMode() throws KNXTimeoutException, KNXPortClosedException, KNXLinkClosedException {
		new BcuSwitcher<>(conn, logger, Function.identity()).normalMode(cEMI);
	}
}
