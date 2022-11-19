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
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static tuwien.auto.calimero.knxnetip.KNXnetIPConnection.BlockingMode.NonBlocking;
import static tuwien.auto.calimero.knxnetip.KNXnetIPConnection.BlockingMode.WaitForAck;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.KNXAckTimeoutException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXListener;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.ServiceType;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.internal.Executor;
import tuwien.auto.calimero.knxnetip.servicetype.DisconnectRequest;
import tuwien.auto.calimero.knxnetip.servicetype.ErrorCodes;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.RoutingIndication;
import tuwien.auto.calimero.knxnetip.servicetype.ServiceRequest;
import tuwien.auto.calimero.knxnetip.util.HPAI;

/**
 * Generic implementation of a KNXnet/IP connection, used for tunneling, device management and routing.
 *
 * @author B. Malinowsky
 */
public abstract class ConnectionBase implements KNXnetIPConnection
{
	/**
	 * Status code of communication: waiting for service acknowledgment after send, no error, not ready to send.
	 */
	public static final int ACK_PENDING = 2;

	/**
	 * Status code of communication: in idle state, received a service acknowledgment error as response, ready to send.
	 */
	public static final int ACK_ERROR = 3;

	// KNXnet/IP client SHALL wait 10 seconds for a connect response frame from server
	static final int CONNECT_REQ_TIMEOUT = 10;

	/** Local control endpoint socket, only assigned and valid if UDP is used. */
	protected DatagramSocket ctrlSocket;
	/** Local data endpoint socket, only assigned and valid if UDP is used. */
	protected DatagramSocket socket;

	/** Remote control endpoint. */
	protected InetSocketAddress ctrlEndpt;
	/** Remote data endpoint. */
	protected InetSocketAddress dataEndpt;

	/** Connection KNX channel identifier. */
	protected int channelId;
	/** Use network address translation (NAT) aware communication. */
	protected boolean useNat;

	/** Service request code used for this connection type. */
	protected final int serviceRequest;
	/** Acknowledgment service type used for this connection type. */
	protected final int serviceAck;
	/** Container for event listeners. */
	protected final EventListeners<KNXListener> listeners = new EventListeners<>();
	/** Logger for this connection. */
	protected Logger logger;

	// current state visible to the user
	// a state < 0 indicates severe error state
	volatile int state = CLOSED;
	/** Internal state, so we can use states not visible to the user. */
	protected volatile int internalState = CLOSED;
	// should an internal state change update the state member
	volatile boolean updateState = true;

	// flag to ensure close is invoked only once
	volatile int closing;

	// number of maximum sends (= retries + 1)
	final int maxSendAttempts;
	// timeout for response message in seconds
	final int responseTimeout;

	CEMI keepForCon;

	private ReceiverLoop receiver;

	// lock object to do wait() on for protocol timeouts
	final ReentrantLock lock = new ReentrantLock(true);
	private final Condition cond = lock.newCondition();

	// send/receive sequence numbers
	private int seqRcv;
	private int seqSend;

	private final Semaphore sendWaitQueue = new Semaphore();
	private boolean inBlockingSend;

	/**
	 * Base constructor to assign the supplied arguments.
	 *
	 * @param serviceRequest service request code of the protocol
	 * @param serviceAck service ack code of the protocol
	 * @param maxSendAttempts maximum send attempts of a datagram
	 * @param responseTimeout response timeout in seconds
	 */
	protected ConnectionBase(final int serviceRequest, final int serviceAck, final int maxSendAttempts,
		final int responseTimeout)
	{
		this.serviceRequest = serviceRequest;
		this.serviceAck = serviceAck;
		this.maxSendAttempts = maxSendAttempts;
		this.responseTimeout = responseTimeout;
	}

	@Override
	public void addConnectionListener(final KNXListener l)
	{
		listeners.add(l);
	}

	@Override
	public void removeConnectionListener(final KNXListener l)
	{
		listeners.remove(l);
	}

	/**
	 * If {@code mode} is {@link BlockingMode#WaitForCon} or {@link BlockingMode#WaitForAck}, the sequence
	 * order of more {@link #send(CEMI, BlockingMode)} calls from different threads is being maintained according to
	 * invocation order (FIFO).<br>
	 * Calling send blocks until any previous invocation finished, then communication proceeds according to the protocol
	 * and waits for response (either ACK or cEMI confirmation), timeout, or an error condition.<br>
	 * Note that, for now, when using blocking mode any ongoing nonblocking invocation is not detected or considered for
	 * waiting until completion.
	 * <p>
	 * If mode is {@link BlockingMode#NonBlocking}, sending is only permitted if no other send is currently being done,
	 * otherwise {@link IllegalStateException} is thrown. In this mode, a user has to check communication state on
	 * its own ({@link #getState()}).
	 */
	@Override
	public void send(final CEMI frame, final BlockingMode mode)
		throws KNXTimeoutException, KNXConnectionClosedException, InterruptedException
	{
		// send state | blocking | nonblocking
		// -----------------------------------
		// OK         |send+wait | send+return
		// WAIT       |wait+s.+w.| throw
		// ACK_ERROR  |send+wait | send+return
		// ERROR      |throw     | throw

		if (state == CLOSED) {
			throw new KNXConnectionClosedException("send attempt on closed connection");
		}
		if (state < 0) {
			logger.log(ERROR, "send invoked in error state " + state + " - aborted");
			throw new IllegalStateException("in error state, send aborted");
		}
		// arrange into line depending on blocking mode
		sendWaitQueue.acquire(mode != NonBlocking);
		lock.lock();
		try {
			if (mode == NonBlocking && state != OK && state != ACK_ERROR) {
				logger.log(WARNING,
						"nonblocking send invoked while waiting for data response in state " + state + " - aborted");
				sendWaitQueue.release(false);
				throw new IllegalStateException("waiting for data response");
			}
			try {
				if (state == CLOSED) {
					throw new KNXConnectionClosedException("send attempt on closed connection");
				}
				updateState = mode == NonBlocking;
				inBlockingSend = mode != NonBlocking;
				final byte[] buf;
				if (serviceRequest == KNXnetIPHeader.ROUTING_IND)
					buf = PacketHelper.toPacket(new RoutingIndication(frame));
				else
					buf = PacketHelper.toPacket(new ServiceRequest<>(serviceRequest, channelId, getSeqSend(), frame));
				keepForCon = frame;
				int attempt = 0;
				for (; attempt < maxSendAttempts; ++attempt) {
					if (logger.isLoggable(TRACE))
						logger.log(TRACE, "sending cEMI frame seq {0}, {1}, attempt {2} (channel {3}) {4}", getSeqSend(), mode,
								(attempt + 1), channelId, DataUnitBuilder.toHex(buf, " "));

					send(buf, dataEndpt);
					// shortcut for routing, don't switch into 'ack-pending'
					if (serviceRequest == KNXnetIPHeader.ROUTING_IND)
						return;
					// skip ack transition if we're using a tcp socket
					if (socket == null) {
						internalState = ClientConnection.CEMI_CON_PENDING;
						break;
					}
					internalState = ACK_PENDING;
					// always forward this state to user
					state = ACK_PENDING;
					if (mode == NonBlocking)
						return;
					waitForStateChange(ACK_PENDING, responseTimeout);
					if (internalState == ClientConnection.CEMI_CON_PENDING || internalState == OK)
						break;
					if (internalState == CLOSED)
						throw new KNXConnectionClosedException("waiting for service ack");
				}
				// close connection on no service ack from server
				if (attempt == maxSendAttempts) {
					final KNXAckTimeoutException e = new KNXAckTimeoutException(
							"maximum send attempts, no service acknowledgment received");
					close(CloseEvent.INTERNAL, "maximum send attempts", ERROR, e);
					throw e;
				}
				// always forward this state to user
				state = internalState;
				if (mode != WaitForAck)
					doExtraBlockingModes();
			}
			catch (final InterruptedIOException e) {
				throw new InterruptedException("interrupted I/O, " + e);
			}
			catch (final IOException e) {
				close(CloseEvent.INTERNAL, "communication failure", ERROR, e);
				throw new KNXConnectionClosedException("connection closed", e);
			}
			finally {
				updateState = true;
				setState(internalState);
				inBlockingSend = false;
				// with routing we immediately release with any blocking mode, because there is no ack/.con
				if (mode != NonBlocking || serviceRequest == KNXnetIPHeader.ROUTING_IND)
					sendWaitQueue.release(mode != NonBlocking);
			}
		}
		finally {
			lock.unlock();
		}
	}

	protected void send(final byte[] packet, final InetSocketAddress dst) throws IOException {
		final DatagramPacket p = new DatagramPacket(packet, packet.length, dst);
		if (dst.equals(dataEndpt))
			socket.send(p);
		else
			ctrlSocket.send(p);
	}

	@Override
	public final InetSocketAddress getRemoteAddress()
	{
		if (state == CLOSED)
			return new InetSocketAddress(0);
		return ctrlEndpt;
	}

	@Override
	public final int getState()
	{
		return state;
	}

	@Override
	public String name()
	{
		// only the control endpoint is set when our logger is initialized (the data
		// endpoint gets assigned later in connect)
		// to keep the name short, avoid a prepended host name as done by InetAddress
		return Net.hostPort(ctrlEndpt);
	}

	@Override
	public final void close()
	{
		close(CloseEvent.USER_REQUEST, "user request", DEBUG, null);
	}

	@Override
	public String toString() {
		return name() + (channelId != 0 ? (" channel " + channelId) : "") + " (state " + connectionState() + ")";
	}

	/**
	 * Returns the protocol's current receive sequence number.
	 *
	 * @return receive sequence number as int
	 */
	protected synchronized int getSeqRcv()
	{
		return seqRcv;
	}

	/**
	 * Increments the protocol's receive sequence number, with increment on sequence number 255 resulting in 0.
	 */
	protected synchronized void incSeqRcv()
	{
		seqRcv = (seqRcv + 1) & 0xFF;
	}

	/**
	 * Returns the protocol's current send sequence number.
	 *
	 * @return send sequence number as int
	 */
	protected synchronized int getSeqSend()
	{
		return seqSend;
	}

	/**
	 * Increments the protocol's send sequence number, with increment on sequence number 255 resulting in 0.
	 */
	protected synchronized void incSeqSend()
	{
		seqSend = (seqSend + 1) & 0xFF;
	}

	/**
	 * Fires a frame received event ({@link KNXListener#frameReceived(FrameEvent)}) for the supplied cEMI
	 * {@code frame}.
	 *
	 * @param frame the cEMI to generate the event for
	 */
	protected void fireFrameReceived(final CEMI frame)
	{
		final FrameEvent fe = new FrameEvent(this, frame);
		listeners.fire(l -> l.frameReceived(fe));
	}

	boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
			final InetSocketAddress source) throws KNXFormatException, IOException {
		final int hdrStart = offset - h.getStructLength();
		logger.log(TRACE, "from {0}: {1}: {2}", Net.hostPort(source), h,
				DataUnitBuilder.toHex(Arrays.copyOfRange(data, hdrStart, hdrStart + h.getTotalLength()), " "));
		return handleServiceType(h, data, offset, source.getAddress(), source.getPort());
	}

	/**
	 * This stub always returns false.
	 *
	 * @param h received KNXnet/IP header
	 * @param data received datagram data
	 * @param offset datagram data start offset
	 * @param src sender IP address
	 * @param port sender UDP port
	 * @return {@code true} if service type was known and handled (successfully or not), {@code false}
	 *         otherwise
	 * @throws KNXFormatException on service type parsing or data format errors
	 * @throws IOException on socket problems
	 */
	@SuppressWarnings("unused")
	protected boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
		final InetAddress src, final int port) throws KNXFormatException, IOException
	{
		// at this subtype level, we don't care about any service type
		return false;
	}

	/**
	 * Request to set this connection into a new connection state.
	 *
	 * @param newState new state to set
	 */
	protected final void setState(final int newState)
	{
		if (closing < 2) {
			//  detect and ignore order of arrival inversion for tunneling.ack/cEMI.con
			if (internalState == OK && newState == ClientConnection.CEMI_CON_PENDING)
				return;
			internalState = newState;
			if (updateState)
				state = newState;
		}
		else
			state = internalState = CLOSED;
	}

	/**
	 * See {@link #setState(int)}, with additional notification of internal threads.
	 *
	 * @param newState new state to set
	 */
	protected final void setStateNotify(final int newState)
	{
		lock.lock();
		try {
			setState(newState);
			if (newState == OK && !inBlockingSend)
				this.sendWaitQueue.release(false);
			// worst case: we notify 2 threads, the closing one and 1 sending
			cond.signalAll();
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Called on {@link #close()}, containing all protocol specific actions to close a connection. Before this method
	 * returns, {@link #cleanup} is called.
	 *
	 * @param initiator one of the constants of {@link CloseEvent}
	 * @param reason short text statement why close was called on this connection
	 * @param level log level to use for logging, adjust this to the reason of closing this connection
	 * @param t a throwable, to pass to the logger if the close event was caused by some error, can be {@code null}
	 */
	protected void close(final int initiator, final String reason, final Level level, final Throwable t)
	{
		synchronized (this) {
			if (closing > 0)
				return;
			closing = 1;
		}
		lock.lock();
		try {
			final boolean tcp = ctrlSocket == null;
			final var hpai = tcp ? HPAI.Tcp : new HPAI(HPAI.IPV4_UDP,
					useNat ? null : (InetSocketAddress) ctrlSocket.getLocalSocketAddress());
			logger.log(TRACE, "sending disconnect request for {0}", this);
			final byte[] buf = PacketHelper.toPacket(new DisconnectRequest(channelId, hpai));
			send(buf, ctrlEndpt);
			long remaining = CONNECT_REQ_TIMEOUT * 1000L;
			final long end = System.currentTimeMillis() + remaining;
			while (closing == 1 && remaining > 0) {
				cond.await(remaining, TimeUnit.MILLISECONDS);
				remaining = end - System.currentTimeMillis();
			}
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		catch (IOException | RuntimeException e) {
			// we have to also catch RTEs here, since if socket already failed
			// before close(), getLocalSocketAddress() might throw illegal argument
			// exception or return the wildcard address, indicating a messed up socket
			logger.log(ERROR, "send disconnect failed", e);
		}
		finally {
			lock.unlock();
		}
		cleanup(initiator, reason, level, t);
	}

	/**
	 * @param initiator one of the constants of {@link CloseEvent}
	 * @param reason short text statement why close was called on this connection
	 * @param level log level to use for logging, adjust this to the reason of closing this connection
	 * @param t a throwable, to pass to the logger if the close event was caused by some error, can be {@code null}
	 */
	protected void cleanup(final int initiator, final String reason, final Level level, final Throwable t)
	{
		setStateNotify(CLOSED);
		fireConnectionClosed(initiator, reason);
		listeners.removeAll();
	}

	protected boolean supportedVersion(final KNXnetIPHeader h)
	{
		final boolean supported = h.getVersion() == KNXnetIPConnection.KNXNETIP_VERSION_10;
		if (!supported)
			logger.log(WARNING, "KNXnet/IP {0}.{1} {2}", h.getVersion() >> 4, h.getVersion() & 0xf,
					ErrorCodes.getErrorMessage(ErrorCodes.VERSION_NOT_SUPPORTED));
		return supported;
	}

	/**
	 * Validates channel id received in a packet against the one assigned to this connection.
	 *
	 * @param id received id to check
	 * @param svcType packet service type
	 * @return {@code true} if valid, {@code false} otherwise
	 */
	protected boolean checkChannelId(final int id, final String svcType)
	{
		if (id == channelId)
			return true;
		logger.log(WARNING, "received service " + svcType + " with wrong channel ID " + id + ", expected " + channelId
				+ " - ignored");
		return false;
	}

	/**
	 * @deprecated No replacement. Use {@link ServiceRequest#from(KNXnetIPHeader, byte[], int)}.
	 */
	@Deprecated
	protected ServiceRequest<ServiceType> getServiceRequest(final KNXnetIPHeader h, final byte[] data, final int offset)
		throws KNXFormatException
	{
		return ServiceRequest.from(h, data, offset);
	}

	final void startReceiver()
	{
		if (receiver == null) {
			final ReceiverLoop looper = new ReceiverLoop(this, socket, 0x200);
			Executor.execute(looper, "KNXnet/IP receiver");
			receiver = looper;
		}
	}

	final void stopReceiver()
	{
		if (receiver != null)
			receiver.quit();
	}

	boolean waitForStateChange(final int initialState, final int timeout) throws InterruptedException
	{
		boolean changed = false;
		long remaining = timeout * 1000L;
		final long end = System.currentTimeMillis() + remaining;
		lock.lock();
		try {
			while (internalState == initialState && remaining > 0) {
				cond.await(remaining, TimeUnit.MILLISECONDS);
				remaining = end - System.currentTimeMillis();
			}
		}
		finally {
			lock.unlock();
		}
		changed = remaining > 0;
		return changed;
	}

	/**
	 * Give chance to perform additional blocking modes called if mode is set to a blocking mode not equal to
	 * NonBlocking and WaitForAck. This method is called from send() after WaitForAck was completed.
	 *
	 * @throws KNXTimeoutException
	 * @throws InterruptedException on interrupted thread
	 */
	@SuppressWarnings("unused")
	void doExtraBlockingModes() throws KNXTimeoutException, InterruptedException {}

	String connectionState() {
		switch (state) {
		case OK: return "OK";
		case CLOSED: return "closed";
		case ACK_PENDING: return "ACK pending";
		case ACK_ERROR: return "ACK error";
		default: return "unknown";
		}
	}

	private void fireConnectionClosed(final int initiator, final String reason)
	{
		final CloseEvent ce = new CloseEvent(this, initiator, reason);
		listeners.fire(l -> l.connectionClosed(ce));
	}

	// a semaphore with fair use behavior (FIFO)
	// acquire and its associated release don't have to be invoked by same thread
	private static final class Semaphore
	{
		private static final class Node
		{
			Node next;
			boolean blocked;

			Node(final Node n)
			{
				next = n;
				blocked = true;
			}
		}

		private Node head;
		private Node tail;
		private int cnt;
		private int nonblockingCnt;

		Semaphore()
		{
			cnt = 1;
			nonblockingCnt = 0;
		}

		void acquire(final boolean blocking)
		{
			final Node n;
			boolean interrupted = false;
			synchronized (this) {
				if (cnt > 0 && tail == null) {
					--cnt;
					if (!blocking)
						nonblockingCnt++;
					return;
				}
				if (!blocking) {
					nonblockingCnt++;
					return;
				}
				n = enqueue();
			}
			synchronized (n) {
				while (n.blocked)
					try {
						n.wait();
					}
					catch (final InterruptedException e) {
						interrupted = true;
					}
			}
			synchronized (this) {
				dequeue();
				--cnt;
			}
			if (interrupted)
				Thread.currentThread().interrupt();
		}

		synchronized void release(final boolean blocking)
		{
			if (blocking) {
				if (++cnt > 0)
					notifyNext();
			}
			else if (nonblockingCnt > 0) {
				nonblockingCnt--;
				if (nonblockingCnt == 0) {
					if (++cnt > 0)
						notifyNext();
				}
			}
		}

		private Node enqueue()
		{
			final Node n = new Node(null);
			if (tail == null)
				tail = n;
			else
				head.next = n;
			head = n;
			return head;
		}

		private void notifyNext()
		{
			if (tail != null)
				synchronized (tail) {
					tail.blocked = false;
					tail.notify();
				}
		}

		private void dequeue()
		{
			tail = tail.next;
			if (tail == null)
				head = null;
		}
	}
}
