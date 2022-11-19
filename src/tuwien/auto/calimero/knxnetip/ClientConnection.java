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

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static tuwien.auto.calimero.knxnetip.Net.hostPort;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXInvalidResponseException;
import tuwien.auto.calimero.KNXRemoteException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.internal.Executor;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectRequest;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectResponse;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectionstateRequest;
import tuwien.auto.calimero.knxnetip.servicetype.ConnectionstateResponse;
import tuwien.auto.calimero.knxnetip.servicetype.DisconnectRequest;
import tuwien.auto.calimero.knxnetip.servicetype.DisconnectResponse;
import tuwien.auto.calimero.knxnetip.servicetype.ErrorCodes;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.ServiceAck;
import tuwien.auto.calimero.knxnetip.util.CRI;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.knxnetip.util.TunnelCRD;
import tuwien.auto.calimero.log.LogService;

/**
 * Base implementation for client tunneling, device management, and routing.
 * <p>
 * The communication on OSI layer 4 is done with UDP or TCP.<br>
 * Implements a communication heartbeat monitor.
 *
 * @author B. Malinowsky
 */
public abstract class ClientConnection extends ConnectionBase
{
	// IMPLEMENTATION NOTE: on MS Windows platforms, interruptible I/O is not supported,
	// i.e., a blocked I/O method remains blocked after interrupt of the thread.
	// To bypass this, we use the rude way to close I/O to force
	// these methods to interrupt and throw.

	/**
	 * Status code of communication: waiting for cEMI confirmation after receive service
	 * acknowledgment, no error, not ready to send.
	 */
	public static final int CEMI_CON_PENDING = 4;

	/**
	 * Status code of communication: unknown error, no send possible.
	 */
	public static final int UNKNOWN_ERROR = -1;

	// request to confirmation timeout
	private static final int CONFIRMATION_TIMEOUT = 3;


	private final HeartbeatMonitor heartbeat = new HeartbeatMonitor();
	private IndividualAddress tunnelingAddress;

	// additional textual information about connection status
	// only set on some errors in receiver, check before using it
	private String status = "";

	private volatile boolean cleanup;

	final boolean tcp;
	private final TcpConnection connection;

	// logger is initialized in connect, when name of connection is available
	protected ClientConnection(final int serviceRequest, final int serviceAck, final int maxSendAttempts,
			final int responseTimeout, final TcpConnection connection) {
		super(serviceRequest, serviceAck, maxSendAttempts, responseTimeout);
		tcp = connection != TcpConnection.Udp;
		this.connection = connection;
	}

	protected ClientConnection(final int serviceRequest, final int serviceAck, final int maxSendAttempts,
			final int responseTimeout) {
		this(serviceRequest, serviceAck, maxSendAttempts, responseTimeout, TcpConnection.Udp);
	}

	protected void connect(final TcpConnection c, final CRI cri) throws KNXException, InterruptedException {
		try {
			c.connect();
			c.registerConnectRequest(this);
			connect(c.localEndpoint(), c.server(), cri, false);
		}
		catch (final IOException e) {
			throw new KNXException("connecting " + connection, e);
		}
		finally {
			c.unregisterConnectRequest(this);
		}
	}

	/**
	 * Opens a new IP communication channel to a remote server.
	 * <p>
	 * The communication state of this object is assumed to be closed state. This method
	 * is designed to be called only once during the objects lifetime!
	 *
	 * @param localEP the local endpoint to use for communication channel
	 * @param serverCtrlEP the remote server control endpoint used for connect request
	 * @param cri connect request information used to configure the communication
	 *        attributes
	 * @param useNAT {@code true} to use a NAT (network address translation) aware
	 *        communication mechanism, {@code false} to use the default way
	 * @throws KNXException on socket communication error
	 * @throws KNXTimeoutException on no connect response before connect timeout
	 * @throws KNXRemoteException if response indicates an error condition at the server
	 *         concerning the request
	 * @throws KNXInvalidResponseException if connect response is in wrong format
	 * @throws InterruptedException on interrupted thread during connect, all resources
	 *         are cleaned up before passing on this exception
	 */
	protected void connect(final InetSocketAddress localEP, final InetSocketAddress serverCtrlEP,
		final CRI cri, final boolean useNAT) throws KNXException, InterruptedException
	{
		if (state != CLOSED)
			throw new IllegalStateException("open connection");
		ctrlEndpt = serverCtrlEP;
		if (ctrlEndpt.isUnresolved())
			throw new KNXException("server control endpoint is unresolved: " + serverCtrlEP);
		if (ctrlEndpt.getAddress().isMulticastAddress())
			throw new KNXIllegalArgumentException("server control endpoint cannot be a multicast address ("
					+ ctrlEndpt.getAddress().getHostAddress() + ")");
		useNat = useNAT;
		logger = LogService.getLogger("calimero.knxnetip." + name());
		// if we allow localEP to be null, we would create an unbound socket
		if (localEP == null)
			throw new KNXIllegalArgumentException("no local endpoint specified");
		final InetSocketAddress local = Net.matchRemoteEndpoint(localEP, serverCtrlEP, useNAT);
		try {
			if (!tcp) {
				socket = new DatagramSocket(local);
				ctrlSocket = socket;
			}

			final var lsa = localSocketAddress();
			logger.log(DEBUG, "establish connection from {0} to {1} ({2})", hostPort(lsa), hostPort(ctrlEndpt), tcp ? "tcp" : "udp");
			// HPAI throws if wildcard local address (0.0.0.0) is supplied
			final var hpai = tcp ? HPAI.Tcp : new HPAI(HPAI.IPV4_UDP, useNat ? null : lsa);
			final byte[] buf = PacketHelper.toPacket(protocolVersion(), new ConnectRequest(cri, hpai, hpai));
			send(buf, ctrlEndpt);
		}
		catch (IOException | SecurityException e) {
			closeSocket();
			logger.log(ERROR, "communication failure on connect", e);
			if (local.getAddress().isLoopbackAddress())
				logger.log(WARNING, "local endpoint uses loopback address ({0}), try with a different IP address",
						local.getAddress());
			throw new KNXException("connecting from " + hostPort(local) + " to " + hostPort(ctrlEndpt) + ": " + e.getMessage());
		}

		logger.log(DEBUG, "wait for connect response from {0} ...", hostPort(ctrlEndpt));
		if (!tcp)
			startReceiver();
		try {
			final boolean changed = waitForStateChange(CLOSED, CONNECT_REQ_TIMEOUT);
			if (state == OK) {
				Executor.execute(heartbeat, "KNXnet/IP heartbeat monitor");

				String optionalConnectionInfo = "";
				if (tunnelingAddress != null)
					optionalConnectionInfo = ", tunneling address " + tunnelingAddress;
				logger.log(INFO, "connection established (data endpoint {0}:{1}, channel {2}{3})",
						dataEndpt.getAddress().getHostAddress(), dataEndpt.getPort(), channelId,
						optionalConnectionInfo);
				return;
			}
			final KNXException e;
			if (!changed)
				e = new KNXTimeoutException("timeout connecting to control endpoint " + hostPort(ctrlEndpt));
			else if (state == ACK_ERROR)
				e = new KNXRemoteException("error response from control endpoint " + hostPort(ctrlEndpt) + ": " + status);
			else
				e = new KNXInvalidResponseException("invalid connect response from " + hostPort(ctrlEndpt));
			// quit, cleanup and notify user
			connectCleanup(e);
			throw e;
		}
		catch (final InterruptedException e) {
			connectCleanup(e);
			throw e;
		}
	}

	@Override
	protected void send(final byte[] packet, final InetSocketAddress dst) throws IOException {
		if (tcp)
			connection.send(packet);
		else
			super.send(packet, dst);
	}

	@Override
	protected void cleanup(final int initiator, final String reason, final Level level,
		final Throwable t)
	{
		// we want close/cleanup be called only once
		synchronized (this) {
			if (cleanup)
				return;
			cleanup = true;
		}

		logger.log(level, "close connection - " + reason, t);
		heartbeat.quit();
		stopReceiver();
		closeSocket();
		// ensure user sees final state CLOSED
		updateState = true;
		super.cleanup(initiator, reason, level, t);
	}

	@Override
	void doExtraBlockingModes() throws KNXTimeoutException, InterruptedException
	{
		// blocking mode is wait for .con
		// wait for incoming request with confirmation
		waitForStateChange(ClientConnection.CEMI_CON_PENDING, ClientConnection.CONFIRMATION_TIMEOUT);
		// throw on no answer
		if (internalState == ClientConnection.CEMI_CON_PENDING) {
			final KNXTimeoutException e = new KNXTimeoutException("no confirmation reply received for " + keepForCon);
			logger.log(WARNING, "response timeout waiting for confirmation", e);
			internalState = OK;
			throw e;
		}
	}

	/**
	 * @see tuwien.auto.calimero.knxnetip.ConnectionBase#handleServiceType
	 *      (tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader, byte[], int, java.net.InetAddress, int)
	 * @throws KNXFormatException if the received service type consists of an invalid structure
	 * @throws IOException on socket I/O error
	 */
	@SuppressWarnings("unused")
	@Override
	protected boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
		final InetAddress src, final int port) throws KNXFormatException, IOException
	{
		final int svc = h.getServiceType();
		if (svc == KNXnetIPHeader.CONNECT_REQ)
			logger.log(WARNING, "received connect request - ignored");
		else if (svc == KNXnetIPHeader.CONNECT_RES) {
			final ConnectResponse res = new ConnectResponse(data, offset);
			// address info is only != null on no error
			final HPAI ep = res.getDataEndpoint();
			if (res.getStatus() == ErrorCodes.NO_ERROR && !(tcp ^ (ep.getHostProtocol() == HPAI.IPV4_TCP))) {
				channelId = res.getChannelID();
				if (tcp) {
					if (!ep.isRouteBack()) {
						final String msg = "connect response from " + src + ":" + port
								+ " does not contain route-back data endpoint";
						close(CloseEvent.INTERNAL, msg, ERROR, null);
						return true;
					}
					dataEndpt = new InetSocketAddress(src, port);
				}
				else if (useNat && (ep.getAddress().isAnyLocalAddress() || ep.getPort() == 0)) {
					// in NAT aware mode, if the data EP is incomplete or left
					// empty, we fall back to the IP address and port of the sender
					dataEndpt = new InetSocketAddress(src, port);
				}
				else {
					dataEndpt = ep.endpoint();
				}

				if (res.getCRD() instanceof TunnelCRD)
					tunnelingAddress = ((TunnelCRD) res.getCRD()).getAssignedAddress();

				checkVersion(h);
				setStateNotify(OK);
				return true;
			}
			if (ep != null && ep.getHostProtocol() != HPAI.IPV4_UDP)
				status = "server does not agree with UDP/IP";
			else
				status = res.getStatusString();

			setStateNotify(ACK_ERROR);
		}
		else if (svc == KNXnetIPHeader.CONNECTIONSTATE_REQ)
			logger.log(WARNING, "received connection state request - ignored");
		else if (svc == KNXnetIPHeader.CONNECTIONSTATE_RES) {
			if (checkVersion(h))
				heartbeat.setResponse(new ConnectionstateResponse(data, offset));
		}
		else if (svc == KNXnetIPHeader.DISCONNECT_REQ) {
			if (ctrlEndpt.getAddress().equals(src) && ctrlEndpt.getPort() == port)
				disconnectRequested(new DisconnectRequest(data, offset));
		}
		else if (svc == KNXnetIPHeader.DISCONNECT_RES) {
			final DisconnectResponse res = new DisconnectResponse(data, offset);
			if (res.getStatus() != ErrorCodes.NO_ERROR)
				logger.log(WARNING, "received disconnect response status 0x"
						+ Integer.toHexString(res.getStatus()) + " ("
						+ ErrorCodes.getErrorMessage(res.getStatus()) + ")");
			// finalize closing
			closing = 2;
			setStateNotify(CLOSED);
		}
		else if (svc == serviceAck) {
			// with tcp, service acks are not required and just ignored
			if (tcp)
				return true;

			final ServiceAck res = new ServiceAck(svc, data, offset);
			if (!checkChannelId(res.getChannelID(), "acknowledgment"))
				return true;
			if (res.getSequenceNumber() != getSeqSend())
				logger.log(WARNING, "received service acknowledgment with wrong send sequence "
						+ res.getSequenceNumber() + ", expected " + getSeqSend() + " - ignored");
			else {
				if (!checkVersion(h))
					return true;
				incSeqSend();
				// update state and notify our lock
				setStateNotify(res.getStatus() == ErrorCodes.NO_ERROR ? CEMI_CON_PENDING : ACK_ERROR);
				logger.log(TRACE, "received service ack {0} from {1} (channel {2})",
						res.getSequenceNumber(), hostPort(ctrlEndpt), channelId);
				if (internalState == ACK_ERROR)
					logger.log(WARNING, "received service acknowledgment status " + res.getStatusString());
			}
		}
		else
			return false;
		return true;
	}

	@Override
	String connectionState() {
		switch (state) {
		case CEMI_CON_PENDING: return "cEMI.con pending";
		case UNKNOWN_ERROR: return "unknown error";
		default: return super.connectionState();
		}
	}

	private InetSocketAddress localSocketAddress() {
		return (InetSocketAddress) (tcp ? connection.localEndpoint() : socket.getLocalSocketAddress());
	}

	private void disconnectRequested(final DisconnectRequest req)
	{
		// requests with wrong channel ID are ignored (conforming to spec)
		if (req.getChannelID() == channelId) {
			final byte[] buf = PacketHelper.toPacket(new DisconnectResponse(channelId, ErrorCodes.NO_ERROR));
			try {
				send(buf, ctrlEndpt);
			}
			catch (final IOException e) {
				logger.log(WARNING, "communication failure", e);
			}
			finally {
				cleanup(CloseEvent.SERVER_REQUEST, "server request", INFO, null);
			}
		}
	}

	protected int protocolVersion() { return KNXNETIP_VERSION_10; }

	/**
	 * Checks for supported protocol version in KNX header.
	 * <p>
	 * On unsupported version,
	 * {@link ClientConnection#close(int, String, Level, Throwable)} is invoked.
	 *
	 * @param h KNX header to check
	 * @return {@code true} on supported version, {@code false} otherwise
	 */
	private boolean checkVersion(final KNXnetIPHeader h)
	{
		if (h.getVersion() != protocolVersion()) {
			status = "protocol version changed";
			close(CloseEvent.INTERNAL, "protocol version changed", ERROR, null);
			return false;
		}
		return true;
	}

	private void connectCleanup(final Exception thrown)
	{
		stopReceiver();
		closeSocket();
		setState(CLOSED);
		String msg = thrown.getMessage();
		msg = msg != null && msg.length() > 0 ? msg : thrown.getClass().getSimpleName();
		logger.log(ERROR, "establishing connection failed, {0}", msg);
	}

	private void closeSocket() {
		if (socket != null)
			socket.close();
	}

	private final class HeartbeatMonitor implements Runnable
	{
		// client SHALL wait 10 seconds for a connection state response from server
		private static final int CONNECTIONSTATE_REQ_TIMEOUT = 10;
		private static final int HEARTBEAT_INTERVAL = 60;
		private static final int MAX_REQUEST_ATTEMPTS = 4;

		private volatile boolean stop;
		private volatile Thread thread;
		private final ReentrantLock lock = new ReentrantLock();
		private final Condition received = lock.newCondition();

		@Override
		public void run()
		{
			thread = Thread.currentThread();
			final var hpai = tcp ? HPAI.Tcp : new HPAI(HPAI.IPV4_UDP, useNat ? null : localSocketAddress());
			final byte[] buf = PacketHelper.toPacket(protocolVersion(), new ConnectionstateRequest(channelId, hpai));
			try {
				while (!stop) {
					Thread.sleep(HEARTBEAT_INTERVAL * 1000);
					int i = 0;
					for (; i < MAX_REQUEST_ATTEMPTS; i++) {
						logger.log(TRACE, "sending connection state request, attempt " + (i + 1));
						lock.lock();
						try {
							send(buf, ctrlEndpt);
							if (received.await(CONNECTIONSTATE_REQ_TIMEOUT, TimeUnit.SECONDS))
								break;
						}
						finally {
							lock.unlock();
						}
					}
					// disconnect on no reply
					if (i == MAX_REQUEST_ATTEMPTS) {
						close(CloseEvent.INTERNAL, "no heartbeat response", WARNING, null);
						break;
					}
				}
			}
			catch (final InterruptedException e) {
				// simply let this thread exit
			}
			catch (final IOException e) {
				close(CloseEvent.INTERNAL, "heartbeat communication failure", ERROR, e);
			}
		}

		void quit()
		{
			stop = true;
			final var t = thread;
			if (t == null)
				return;
			t.interrupt();
			if (Thread.currentThread() == t)
				return;
			try {
				t.join();
			}
			catch (final InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}

		void setResponse(final ConnectionstateResponse res)
		{
			if (res.getStatus() == ErrorCodes.NO_ERROR) {
				lock.lock();
				try {
					received.signal();
				}
				finally {
					lock.unlock();
				}
			}
			else
				logger.log(WARNING, "connection state response: {0} (channel {1})", res.getStatusString(), channelId);
		}
	}
}
