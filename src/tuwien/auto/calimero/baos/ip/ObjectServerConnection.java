/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2021, 2022 B. Malinowsky

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

package tuwien.auto.calimero.baos.ip;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXListener;
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.baos.BaosService;
import tuwien.auto.calimero.baos.BaosService.Property;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.knxnetip.ClientConnection;
import tuwien.auto.calimero.knxnetip.KNXConnectionClosedException;
import tuwien.auto.calimero.knxnetip.TcpConnection;
import tuwien.auto.calimero.knxnetip.servicetype.ErrorCodes;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.ServiceAck;
import tuwien.auto.calimero.knxnetip.servicetype.ServiceRequest;
import tuwien.auto.calimero.knxnetip.util.CRI;
import tuwien.auto.calimero.log.LogService;

/**
 * KNX IP ObjectServer connection for connecting to BAOS-capable servers.
 * <p>
 * The object server protocol specifies a point-to-point exchange of object server messages over an IP network
 * connection between two KNXnet/IP devices -- client and server. The communication on OSI layer 4 uses UDP or TCP.
 */
class ObjectServerConnection extends ClientConnection {
	interface ObjectServerListener extends KNXListener {
		void baosService(BaosService svc);

		@Override
		default void frameReceived(final FrameEvent e) {}
	}

	private static final int ObjectServerProtocol = 0xf0;
	private static final int ProtocolVersion = 0x20;

	// client SHALL wait 1 second for acknowledgment response to a object server request from server
	private static final int ReqTimeout = 1;

	private final boolean tcp;
	private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
	private final Future<?> keepAlive;


	ObjectServerConnection(final InetSocketAddress localEP, final InetSocketAddress serverCtrlEP)
			throws KNXException, InterruptedException {
		super(KNXnetIPHeader.ObjectServerRequest, KNXnetIPHeader.ObjectServerAck, 2, ReqTimeout);
		tcp = false;
		keepAlive = CompletableFuture.completedFuture(Void.TYPE);
		connect(localEP, serverCtrlEP, CRI.createRequest(ObjectServerProtocol), false);
	}

	ObjectServerConnection(final TcpConnection c) throws KNXException {
		super(KNXnetIPHeader.ObjectServerRequest, KNXnetIPHeader.ObjectServerAck, 1, ReqTimeout, c);
		ctrlEndpt = c.server();
		logger = LogService.getLogger("calimero.baos." + name());
		tcp = true;
		try {
			c.connect();
		}
		catch (final IOException e) {
			throw new KNXException("connecting " + c, e);
		}
		setState(OK);
		keepAlive = scheduler.scheduleAtFixedRate(this::sendKeepAlive, 2, 60, TimeUnit.SECONDS);
		c.registerConnection(this);
	}

	/**
	 * Throws {@link UnsupportedOperationException}.
	 *
	 * @param frame cEMI unused
	 * @param mode unused
	 */
	@Override
	public void send(final CEMI frame, final BlockingMode mode) {
		throw new UnsupportedOperationException("object server protocol does not support cEMI");
	}

	/**
	 * Sends the object server protocol service to the connected BAOS server.
	 *
	 * @param svc object server protocol service
	 * @throws KNXConnectionClosedException
	 */
	public void send(final BaosService svc, final BlockingMode mode) throws KNXConnectionClosedException {
		if (mode == BlockingMode.WaitForCon)
			throw new KNXIllegalArgumentException(mode + " is not supported");
		try {
			final int chid = tcp ? 0 : channelId;
			final int seq = tcp ? 0 : getSeqSend();
			final var buf = PacketHelper.toPacket(new ServiceRequest<>(serviceRequest, chid, seq, svc));

			// NYI udp: we need a send method like for cEMI
			send(buf, dataEndpt);
		}
		catch (final IOException e) {
			close(CloseEvent.INTERNAL, "communication failure", ERROR, e);
			throw new KNXConnectionClosedException("connection closed", e);
		}
	}

	@Override
	public String getName() {
		return "KNX IP ObjectServer " + super.name();
	}

	@Override
	protected boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
		final InetAddress src, final int port) throws KNXFormatException, IOException {
		if (super.handleServiceType(h, data, offset, src, port))
			return true;
		final int svc = h.getServiceType();
		if (svc < serviceRequest || svc > serviceAck)
			return false;

		final Function<ByteBuffer, BaosService> objectServerParser = buf -> {
			try {
				return BaosService.from(buf);
			}
			catch (final KNXFormatException e) {
				throw new KnxRuntimeException("parsing BAOS service", e);
			}
		};

		final var req = ServiceRequest.from(h, data, offset, objectServerParser);
		if (!checkChannelId(req.getChannelID(), "request"))
			return true;

		// req sequence and ack is only used over udp connections, not tcp
		if (!tcp) {
			final int seq = req.getSequenceNumber();
			final boolean expected = seq == getSeqRcv();
			final boolean repeated = ((seq + 1) & 0xFF) == getSeqRcv();

			// send KNXnet/IP service ack
			if (expected || repeated) {
				final int status = h.getVersion() == ProtocolVersion ? ErrorCodes.NO_ERROR
						: ErrorCodes.VERSION_NOT_SUPPORTED;
				final byte[] buf = PacketHelper.toPacket(new ServiceAck(serviceAck, channelId, seq, status));
				send(buf, dataEndpt);
				if (status == ErrorCodes.VERSION_NOT_SUPPORTED) {
					close(CloseEvent.INTERNAL, "protocol version changed", ERROR, null);
					return true;
				}
			}
			else {
				logger.log(WARNING, "object server request with invalid rcv-seq {0}, expected {1}", seq, getSeqRcv());
				return true;
			}

			// ignore repeated object server requests
			if (repeated) {
				logger.log(DEBUG, "skip object server request with rcv-seq {0} (already received)", seq);
				return true;
			}

			incSeqRcv();
		}

		final var objSvrService = req.service();
		if (objSvrService.isResponse() || objSvrService.subService() == BaosService.DatapointValueIndication
				|| objSvrService.subService() == BaosService.ServerItemIndication) {
			logger.log(TRACE, "received request seq {0} (channel {1}) svc {2}", req.getSequenceNumber(), channelId,
					objSvrService);
			fireFrameReceived(objSvrService);
		}
		else
			logger.log(WARNING, "received object server request - ignore {0}", objSvrService);

		return true;
	}

	@Override
	protected void close(final int initiator, final String reason, final Level level, final Throwable t) {
		if (tcp) {
//			closing = 2; // XXX needed?
			cleanup(initiator, reason, level, t);
			keepAlive.cancel(true);
			scheduler.shutdown();
		}
		else
			super.close(initiator, reason, level, t);
	}

	@Override
	protected int protocolVersion() { return 0x20; }

	private void fireFrameReceived(final BaosService objSvrService) {
		listeners.listeners().stream().filter(ObjectServerListener.class::isInstance)
				.map(ObjectServerListener.class::cast).forEach(l -> l.baosService(objSvrService));
	}

	private void sendKeepAlive() {
		try {
			send(BaosService.getServerItem(Property.TimeSinceReset, 1), BlockingMode.NonBlocking);
		}
		catch (final KNXConnectionClosedException ignore) {}
	}
}
