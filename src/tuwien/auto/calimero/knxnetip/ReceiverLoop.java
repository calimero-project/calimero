/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2022 B. Malinowsky

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

package tuwien.auto.calimero.knxnetip;

import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.WARNING;

import java.io.IOException;
import java.lang.System.Logger;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.internal.UdpSocketLooper;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;

class ReceiverLoop extends UdpSocketLooper implements Runnable
{
	private final ConnectionBase conn;
	private final Logger logger;

	// precondition: an initialized logger instance in ConnectionBase
	ReceiverLoop(final ConnectionBase connection, final DatagramSocket socket,
		final int receiveBufferSize)
	{
		this(connection, socket, receiveBufferSize, 0, 0);
	}

	// precondition: an initialized logger instance in ConnectionBase
	ReceiverLoop(final ConnectionBase connection, final DatagramSocket socket, final int receiveBufferSize,
		final int socketTimeout, final int loopTimeout) {
		super(socket, true, receiveBufferSize, socketTimeout, loopTimeout);
		conn = connection;
		logger = connection.logger;
	}

	@Override
	public void run()
	{
		try {
			loop();
		}
		catch (final IOException e) {
			conn.close(CloseEvent.INTERNAL, "receiver communication failure", ERROR, e);
		}
	}

	@Override
	protected void onReceive(final InetSocketAddress source, final byte[] data,
		final int offset, final int length) throws IOException
	{
		try {
			final KNXnetIPHeader h = KNXnetIPHeader.from(data, offset);
			if (h.getTotalLength() > length)
				logger.log(WARNING, "received frame length " + length + " for " + h + " - ignored");
			else if (h.getServiceType() == 0)
				// check service type for 0 (invalid type), so unused service types of us can stay 0 by default
				logger.log(WARNING, "received frame with service type 0x0 - ignored");
			else if (!conn.handleServiceType(h, data, offset + h.getStructLength(), source))
				logger.log(INFO, "received unknown frame with service type 0x"
						+ Integer.toHexString(h.getServiceType()) + " - ignored");
		}
		catch (KNXFormatException | RuntimeException e) {
			logger.log(WARNING, "received invalid frame", e);
		}
	}
}
