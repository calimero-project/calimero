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

package tuwien.auto.calimero.knxnetip;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static tuwien.auto.calimero.knxnetip.KNXnetIPTunnel.TunnelingLayer.BusMonitorLayer;
import static tuwien.auto.calimero.knxnetip.KNXnetIPTunnel.TunnelingLayer.RawLayer;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAckTimeoutException;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXInvalidResponseException;
import tuwien.auto.calimero.KNXRemoteException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.cemi.AdditionalInfo;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIBusMon;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.cemi.CEMILDataEx;
import tuwien.auto.calimero.knxnetip.servicetype.ErrorCodes;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.servicetype.ServiceAck;
import tuwien.auto.calimero.knxnetip.servicetype.ServiceRequest;
import tuwien.auto.calimero.knxnetip.servicetype.TunnelingFeature;
import tuwien.auto.calimero.knxnetip.servicetype.TunnelingFeature.InterfaceFeature;
import tuwien.auto.calimero.knxnetip.util.TunnelCRI;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.log.LogService;

/**
 * KNXnet/IP connection for KNX tunneling.
 * <p>
 * The tunneling protocol specifies a point-to-point exchange of KNX frames over an IP
 * network connection between two KNXnet/IP devices - client and server. Communication on OSI layer 4 uses UDP or TCP.
 *
 * @author B. Malinowsky
 */
public class KNXnetIPTunnel extends ClientConnection
{
	/**
	 * Connection type used to tunnel between two KNXnet/IP devices (client / server).
	 */
	public static final int TUNNEL_CONNECTION = 0x04;


	public enum TunnelingLayer {
		/**
		 * Tunneling on busmonitor layer, establishes a busmonitor tunnel to the KNX network.
		 */
		BusMonitorLayer(0x80),
		/**
		 * Tunneling on link layer, establishes a link layer tunnel to the KNX network.
		 */
		LinkLayer(0x02),
		/**
		 * Tunneling on raw layer, establishes a raw tunnel to the KNX network.
		 */
		RawLayer(0x04);

		private final int code;

		public static TunnelingLayer from(final int layer)
		{
			for (final TunnelingLayer v : TunnelingLayer.values())
				if (layer == v.code)
					return v;
			throw new KNXIllegalArgumentException("unspecified tunneling layer + 0x" + Integer.toHexString(layer));
		}

		TunnelingLayer(final int code) {
			this.code = code;
		}

		public final int getCode() {
			return code;
		}
	}

	// client SHALL wait 1 second for acknowledgment response to a
	// tunneling request from server
	private static final int TUNNELING_REQ_TIMEOUT = 1;

	private final TunnelingLayer layer;


	public static KNXnetIPTunnel newTcpTunnel(final TunnelingLayer knxLayer, final TcpConnection connection,
			final IndividualAddress tunnelingAddress) throws KNXException, InterruptedException {
		return new KNXnetIPTunnel(knxLayer, connection, tunnelingAddress);
	}

	/**
	 * Creates a new KNXnet/IP tunneling connection to a remote server.
	 * <p>
	 * Establishing a raw tunneling layer (
	 * {@link tuwien.auto.calimero.knxnetip.KNXnetIPTunnel.TunnelingLayer#RawLayer}) is not
	 * supported yet.<br>
	 *
	 * @param knxLayer KNX tunneling layer (e.g. {@link TunnelingLayer#LinkLayer})
	 * @param localEP specifies the local endpoint with the socket address to be used by the tunnel
	 * @param serverCtrlEP control endpoint of the server to establish connection to
	 * @param useNAT {@code true} to use a NAT (network address translation) aware
	 *        communication mechanism, {@code false} to use the default way
	 * @throws KNXException on socket communication error
	 * @throws KNXTimeoutException on no connect response before connect timeout
	 * @throws KNXRemoteException if response indicates an error condition at the server concerning
	 *         the request
	 * @throws KNXInvalidResponseException if connect response is in wrong format
	 * @throws InterruptedException on interrupted thread while creating tunneling connection
	 */
	public KNXnetIPTunnel(final TunnelingLayer knxLayer, final InetSocketAddress localEP,
		final InetSocketAddress serverCtrlEP, final boolean useNAT) throws KNXException,
		InterruptedException
	{
		this(knxLayer, localEP, serverCtrlEP, useNAT, KNXMediumSettings.BackboneRouter);
	}

	KNXnetIPTunnel(final TunnelingLayer knxLayer, final InetSocketAddress localEP, final InetSocketAddress serverCtrlEP,
		final boolean useNAT, final IndividualAddress tunnelingAddress) throws KNXException, InterruptedException {
		this(knxLayer, serverCtrlEP);
		final var cri = tunnelingAddress.equals(KNXMediumSettings.BackboneRouter) ? new TunnelCRI(knxLayer)
				: new TunnelCRI(knxLayer, tunnelingAddress);
		connect(localEP, serverCtrlEP, cri, useNAT);
	}

	protected KNXnetIPTunnel(final TunnelingLayer knxLayer, final TcpConnection connection,
			final IndividualAddress tunnelingAddress) throws KNXException, InterruptedException {
		super(KNXnetIPHeader.TUNNELING_REQ, KNXnetIPHeader.TUNNELING_ACK, 1, TUNNELING_REQ_TIMEOUT, connection);
		layer = Objects.requireNonNull(knxLayer, "Tunneling Layer");
		if (knxLayer == RawLayer)
			throw new KNXIllegalArgumentException("Raw tunnel to KNX network not supported");

		final var cri = tunnelingAddress.equals(KNXMediumSettings.BackboneRouter) ? new TunnelCRI(knxLayer)
				: new TunnelCRI(knxLayer, tunnelingAddress);
		connect(connection, cri);
	}

	KNXnetIPTunnel(final TunnelingLayer knxLayer, final InetSocketAddress serverCtrlEP) throws KNXException {
		super(KNXnetIPHeader.TUNNELING_REQ, KNXnetIPHeader.TUNNELING_ACK, 2, TUNNELING_REQ_TIMEOUT);
		layer = Objects.requireNonNull(knxLayer, "Tunneling Layer");
		if (knxLayer == RawLayer)
			throw new KNXIllegalArgumentException("Raw tunnel to KNX network not supported");
		ctrlEndpt = serverCtrlEP;
		if (ctrlEndpt.isUnresolved())
			throw new KNXException("server control endpoint is unresolved: " + serverCtrlEP);
		logger = LogService.getLogger("calimero.knxnetip." + name());
	}

	/**
	 * Sends a cEMI frame to the remote server communicating with this endpoint.
	 * <p>
	 * Sending in busmonitor mode is not permitted.<br>
	 *
	 * @param frame cEMI message to send, the expected cEMI type is according to the used
	 *        tunneling layer
	 */
	@Override
	public void send(final CEMI frame, final BlockingMode mode)
		throws KNXTimeoutException, KNXConnectionClosedException, InterruptedException
	{
		if (layer == BusMonitorLayer)
			throw new IllegalStateException("send not permitted in busmonitor mode");
		if (!(frame instanceof CEMILData))
			throw new KNXIllegalArgumentException("unsupported cEMI type " + frame.getClass());
		super.send(frame, mode);
	}

	// sends a tunneling feature-get service
	// sendFeature / getFeature?
	public void send(final InterfaceFeature feature) throws KNXConnectionClosedException, KNXTimeoutException,
			InterruptedException {
		lock.lock();
		try {
			final TunnelingFeature get = TunnelingFeature.newGet(feature);
			send(get);
		}
		finally {
			lock.unlock();
		}
	}

	// sends a tunneling feature-set service
	// sendFeature / setFeature?
	public void send(final InterfaceFeature feature, final byte... featureValue)
		throws KNXConnectionClosedException, KNXTimeoutException, InterruptedException {
		lock.lock();
		try {
			final TunnelingFeature set = TunnelingFeature.newSet(feature, featureValue);
			send(set);
		}
		finally {
			lock.unlock();
		}
	}

	// pre-cond: send lock hold
	// pre-cond: there is no cEMI send in progress, cEMI frames use the ConnectionBase::sendWaitQueue
	private void send(final TunnelingFeature tunnelingFeature)
		throws KNXConnectionClosedException, KNXTimeoutException, InterruptedException {
		if (layer == TunnelingLayer.BusMonitorLayer)
			throw new IllegalStateException("send not permitted in busmonitor mode");
		if (state < 0)
			throw new IllegalStateException("in error state, send aborted");
		if (state == CLOSED)
			throw new KNXConnectionClosedException("send attempt on closed connection");

//		sendWaitQueue.acquire(true);

		final var req = new ServiceRequest<>(tunnelingFeature.type(), channelId, getSeqSend(), tunnelingFeature);
		final byte[] buf = PacketHelper.toPacket(req);
		try {
			int attempt = 0;
			for (; attempt < maxSendAttempts; ++attempt) {
				logger.log(TRACE, "sending {0}, attempt {1}", tunnelingFeature, attempt + 1);
				updateState = false;

				send(buf, dataEndpt);
				// skip ack transition if we're using a tcp socket
				if (socket == null) {
					internalState = ClientConnection.CEMI_CON_PENDING;
					break;
				}
				internalState = ACK_PENDING;
				// always forward this state to user
				state = ACK_PENDING;
				waitForStateChange(ACK_PENDING, responseTimeout);
				if (internalState == ClientConnection.CEMI_CON_PENDING || internalState == OK)
					break;
			}
			if (attempt == maxSendAttempts) {
				final var e = new KNXAckTimeoutException("maximum send attempts, no service acknowledgment received");
				close(CloseEvent.INTERNAL, "maximum send attempts", ERROR, e);
				throw e;
			}
			// always forward this state to user
			state = internalState;
			waitForTunnelingFeatureResponse(tunnelingFeature);
		}
		catch (final InterruptedIOException e) {
			throw new InterruptedException("interrupted I/O, " + e);
		}
		catch (final IOException e) {
			close(CloseEvent.INTERNAL, "communication failure", ERROR, e);
			throw new KNXConnectionClosedException("connection closed");
		}
		finally {
			updateState = true;
			setState(OK);
		}
	}

	private void waitForTunnelingFeatureResponse(final TunnelingFeature tf) throws KNXTimeoutException,
			InterruptedException {
		// wait for incoming request with feature response
		waitForStateChange(ClientConnection.CEMI_CON_PENDING, 3);
		// throw on no answer
		if (internalState == ClientConnection.CEMI_CON_PENDING) {
			logger.log(WARNING, "response timeout waiting for response to {0}", tf);
			internalState = OK;
			throw new KNXTimeoutException("no response received for " + tf);
		}
	}

	@Override
	public String name()
	{
		return "KNXnet/IP Tunneling " + super.name();
	}

	@Override
	protected boolean handleServiceType(final KNXnetIPHeader h, final byte[] data, final int offset,
		final InetAddress src, final int port) throws KNXFormatException, IOException
	{
		if (super.handleServiceType(h, data, offset, src, port))
			return true;
		final int svc = h.getServiceType();
		// { tunneling.req/ack, tunneling-feat.x }
		if (svc < serviceRequest || svc > KNXnetIPHeader.TunnelingFeatureInfo)
			return false;

		final var req = ServiceRequest.from(h, data, offset);
		if (!checkChannelId(req.getChannelID(), "request"))
			return true;

		// tunneling sequence and ack is only used over udp connections, not tcp
		if (!tcp) {
			final int seq = req.getSequenceNumber();
			final boolean missed = ((seq - 1) & 0xFF) == getSeqRcv();
			if (missed) {
				// Workaround for missed request problem (not part of the knxnet/ip tunneling spec):
				// we missed a single request, hence, the receive sequence is one behind. If the remote
				// endpoint didn't terminate the connection, but continues to send requests, this workaround
				// re-syncs with the sequence of the sender.
				final String s = System.getProperty("calimero.knxnetip.tunneling.resyncSkippedRcvSeq");
				final boolean resync = "".equals(s) || "true".equalsIgnoreCase(s);
				if (resync) {
					logger.log(ERROR, "tunneling request with rcv-seq " + seq + ", expected " + getSeqRcv()
							+ " -> re-sync with server (1 tunneled msg lost)");
					incSeqRcv();
				}
			}
			final boolean expected = seq == getSeqRcv();
			final boolean repeated = ((seq + 1) & 0xFF) == getSeqRcv();

			// send KNXnet/IP service ack
			if (expected || repeated) {
				final int status = h.getVersion() == KNXNETIP_VERSION_10 ? ErrorCodes.NO_ERROR
						: ErrorCodes.VERSION_NOT_SUPPORTED;
				final byte[] buf = PacketHelper.toPacket(new ServiceAck(serviceAck, channelId, seq, status));
				send(buf, dataEndpt);
				if (status == ErrorCodes.VERSION_NOT_SUPPORTED) {
					close(CloseEvent.INTERNAL, "protocol version changed", ERROR, null);
					return true;
				}
			}
			else {
				logger.log(WARNING, "tunneling request with invalid rcv-seq {0}, expected {1}", seq, getSeqRcv());
				return true;
			}

			// ignore repeated tunneling requests
			if (repeated) {
				logger.log(DEBUG, "skip tunneling request with rcv-seq {0} (already received)", seq);
				return true;
			}

			incSeqRcv();
		}

		if (svc >= KNXnetIPHeader.TunnelingFeatureGet && svc <= KNXnetIPHeader.TunnelingFeatureInfo) {
			final TunnelingFeature feature = req.service();
			logger.log(TRACE, "received {0}", feature);
			setStateNotify(OK);

			listeners.listeners().stream().filter(TunnelingListener.class::isInstance)
					.map(TunnelingListener.class::cast).forEach(tl -> notifyFeatureReceived(tl, svc, feature));
			return true;
		}

		final CEMI cemi = req.service();
		final int mc = cemi.getMessageCode();
		if (mc == CEMILData.MC_LDATA_IND || mc == CEMIBusMon.MC_BUSMON_IND) {
			logger.log(TRACE, "received request seq {0} (channel {1}) cEMI {2}", req.getSequenceNumber(), channelId,
					DataUnitBuilder.toHex(cemi.toByteArray(), " "));
			fireFrameReceived(cemi);
		}
		else if (mc == CEMILData.MC_LDATA_CON) {
			// invariant: notify listener before return from blocking send
			logger.log(DEBUG, "received request seq {0} (channel {1}) cEMI L-Data.con {2}->{3}", req.getSequenceNumber(),
					channelId, ((CEMILData) cemi).getSource(), ((CEMILData) cemi).getDestination());
			// TODO move notification to after we know it's a valid .con (we should keep it out of the lock, though)
			fireFrameReceived(cemi);

			lock.lock();
			try {
				final CEMILData ldata = (CEMILData) keepForCon;
				if (ldata != null && internalState == CEMI_CON_PENDING) {
					// check if address was set by server
					final boolean emptySrc = ldata.getSource().getRawAddress() == 0;
					final List<Integer> types = additionalInfoTypesOf(ldata);
					final byte[] sent = unifyLData(ldata, emptySrc, types);
					final byte[] recv = unifyLData(cemi, emptySrc, types);
					if (Arrays.equals(recv, sent)) {
						keepForCon = null;
						setStateNotify(OK);
					}
					else {
						// we could get a .con with its hop count already decremented by 1 (eibd does that)
						// decrement hop count of sent for comparison
						final int sendCount = ldata.getHopCount() - 1;
						sent[3] = (byte) ((sent[3] & (0x8f)) | (sendCount << 4));
						if (Arrays.equals(recv, sent)) {
							keepForCon = null;
							setStateNotify(OK);
							logger.log(INFO, "received L_Data.con with hop count decremented by 1 (sent {0}, got {2})",
									sendCount + 1, sendCount);
						}
					}
				}
			}
			finally {
				lock.unlock();
			}
		}
		else if (mc == CEMILData.MC_LDATA_REQ)
			logger.log(WARNING, "received L-Data request - ignore {0}", cemi);

		return true;
	}

	private void notifyFeatureReceived(final TunnelingListener tl, final int svc, final TunnelingFeature feature) {
		try {
			if (svc == KNXnetIPHeader.TunnelingFeatureResponse)
				tl.featureResponse(feature);
			else if (svc == KNXnetIPHeader.TunnelingFeatureInfo)
				tl.featureInfo(feature);
			else
				logger.log(WARNING, "unsupported {0} - ignored", feature);
		}
		catch (final RuntimeException rte) {
			logger.log(WARNING, "catch your runtime exceptions in {0}!", tl.getClass().getName(), rte);
		}
	}

	private static List<Integer> additionalInfoTypesOf(final CEMILData ldata)
	{
		if (ldata instanceof CEMILDataEx) {
			final CEMILDataEx ext = (CEMILDataEx) ldata;
			return ext.additionalInfo().stream().map(AdditionalInfo::type).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	// types parameter: a workaround introduced for the Gira server, which sometimes adds non-standard
	// additional info. types provides the list of add.info types we want to keep, everything else is removed
	private byte[] unifyLData(final CEMI ldata, final boolean emptySrc, final List<Integer> types)
	{
		final byte[] data;
		if (ldata instanceof CEMILDataEx) {
			final CEMILDataEx ext = ((CEMILDataEx) ldata);
			final var additionalInfo = ext.additionalInfo();
			synchronized (additionalInfo) {
				for (final var i = additionalInfo.iterator(); i.hasNext();) {
					final AdditionalInfo info = i.next();
					if (!types.contains(info.type())) {
						logger.log(WARNING, "remove L-Data additional info {0}", info);
						i.remove();
					}
				}
			}
		}
		data = ldata.toByteArray();
		// set msg code field 0
		data[0] = 0;
		// set ctrl1 field 0
		data[1 + data[1] + 1] = 0;
		// conditionally set source address 0
		if (emptySrc) {
			data[1 + data[1] + 3] = 0;
			data[1 + data[1] + 4] = 0;
		}
		return data;
	}
}
