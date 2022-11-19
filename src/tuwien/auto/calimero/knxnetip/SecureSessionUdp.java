/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2018, 2022 B. Malinowsky

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
import static tuwien.auto.calimero.DataUnitBuilder.toHex;
import static tuwien.auto.calimero.knxnetip.Net.hostPort;
import static tuwien.auto.calimero.knxnetip.SecureConnection.secureSymbol;

import java.io.IOException;
import java.lang.System.Logger;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.XECPublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.SerialNumber;
import tuwien.auto.calimero.knxnetip.TcpConnection.SecureSession;
import tuwien.auto.calimero.knxnetip.servicetype.KNXnetIPHeader;
import tuwien.auto.calimero.knxnetip.servicetype.PacketHelper;
import tuwien.auto.calimero.knxnetip.util.HPAI;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.secure.KnxSecureException;

final class SecureSessionUdp {
	// timeout session.req -> session.res, and session.auth -> session.status
	private static final int sessionSetupTimeout = 10_000; // [ms]

	// session status codes
	private static final int AuthSuccess = 0;
	private static final int AuthFailed = 1;
	// internal session status we use for initial setup
	private static final int Setup = 6;


	private final SecureSession session;
	private final Logger logger;

	private Key secretKey;
	private PrivateKey privateKey;
	private final byte[] publicKey = new byte[SecureConnection.keyLength];

	private int sessionId;
	private volatile int sessionStatus = Setup;

	private DatagramSocket localSocket;
	private ReceiverLoop setupLoop;


	SecureSessionUdp(final int userId, final byte[] userKey, final byte[] deviceAuthCode,
			final InetSocketAddress serverCtrlEP) {
		session = TcpConnection.Udp.newSecureSession(userId, userKey, deviceAuthCode);
		this.logger = LogService.getLogger(
				"calimero.knxnetip.KNX/IP " + SecureConnection.secureSymbol + " Session " + hostPort(serverCtrlEP));
	}

	// session.req -> session.res -> auth.req -> session-status
	void setupSecureSession(final ClientConnection conn, final InetSocketAddress localEP,
			final InetSocketAddress serverCtrlEP, final boolean useNat)
		throws KNXException {

		logger.log(DEBUG, "setup secure session with {0}", serverCtrlEP);
		try {
			final KeyPair keyPair = SecureConnection.generateKeyPair();
			privateKey = keyPair.getPrivate();
			final BigInteger u = ((XECPublicKey) keyPair.getPublic()).getU();
			final byte[] tmp = u.toByteArray();
			SecureConnection.reverse(tmp);
			System.arraycopy(tmp, 0, publicKey, 0, tmp.length);
		}
		catch (final Throwable e) {
			throw new KnxSecureException("error creating secure key pair for " + serverCtrlEP, e);
		}
		try (DatagramSocket local = new DatagramSocket(localEP)) {
			localSocket = local;
			final HPAI hpai = new HPAI(HPAI.IPV4_UDP,
					useNat ? null : (InetSocketAddress) local.getLocalSocketAddress());
			final byte[] sessionReq = PacketHelper.newChannelRequest(hpai, publicKey);
			local.send(new DatagramPacket(sessionReq, sessionReq.length, serverCtrlEP));

			setupLoop = new ReceiverLoop(conn, local, 512, 0, sessionSetupTimeout);
			setupLoop.run();
			if (sessionStatus == Setup)
				throw new KNXTimeoutException("timeout establishing secure session with " + serverCtrlEP);
			if (sessionStatus != AuthSuccess)
				throw new KnxSecureException("secure session " + SecureConnection.statusMsg(sessionStatus));
		}
		catch (final IOException e) {
			throw new KNXException("I/O error establishing secure session with " + serverCtrlEP, e);
		}
		finally {
			Arrays.fill(publicKey, (byte) 0);
			// key.destroy() is not implemented
//				try {
//					privateKey.destroy();
//				}
//				catch (final DestroyFailedException e) {}
		}
	}

	void sessionAuth(final KNXnetIPHeader h, final byte[] data, final int offset, final InetSocketAddress source)
			throws KNXFormatException, IOException {
		try {
			final Object[] res = newSessionResponse(h, data, offset, source);

			final byte[] serverPublicKey = (byte[]) res[1];
			final byte[] auth = newSessionAuth(serverPublicKey);
			final byte[] packet = newSecurePacket(auth);
			logger.log(DEBUG, "secure session {0}, request access for user {1}", sessionId, session.user());
			localSocket.send(new DatagramPacket(packet, packet.length, source));
		}
		catch (final RuntimeException e) {
			sessionStatus = AuthFailed;
			quitSetupLoop();
			logger.log(ERROR, "negotiating session key failed", e);
		}
	}

	Object[] newSessionResponse(final KNXnetIPHeader h, final byte[] data, final int offset,
		final InetSocketAddress src) throws KNXFormatException {

		if (h.getServiceType() != SecureConnection.SecureSessionResponse)
			throw new KNXIllegalArgumentException("no secure channel response");
		if (h.getTotalLength() != 0x38 && h.getTotalLength() != 0x08)
			throw new KNXFormatException("invalid length " + data.length + " for a secure channel response");

		final ByteBuffer buffer = ByteBuffer.wrap(data, offset, h.getTotalLength() - h.getStructLength());

		sessionId = buffer.getShort() & 0xffff;
		if (sessionId == 0)
			throw new KnxSecureException("no more free secure channels / remote endpoint busy");

		final byte[] serverPublicKey = new byte[SecureConnection.keyLength];
		buffer.get(serverPublicKey);

		final byte[] sharedSecret = SecureConnection.keyAgreement(privateKey, serverPublicKey);
		final byte[] sessionKey = SecureConnection.sessionKey(sharedSecret);
		secretKey = SecureConnection.createSecretKey(sessionKey);

		final boolean skipDeviceAuth = Arrays.equals(session.deviceAuthKey().getEncoded(), new byte[16]);
		if (skipDeviceAuth) {
			logger.log(WARNING, "skipping device authentication of {0} (no device key)", hostPort(src));
		}
		else {
			final ByteBuffer mac = SecureConnection.decrypt(buffer, session.deviceAuthKey(),
					SecureConnection.securityInfo(new byte[16], 0, 0xff00));

			final int msgLen = h.getStructLength() + 2 + SecureConnection.keyLength;
			final ByteBuffer macInput = ByteBuffer.allocate(16 + 2 + msgLen);
			macInput.put(new byte[16]);
			macInput.put((byte) 0);
			macInput.put((byte) msgLen);
			macInput.put(h.toByteArray());
			macInput.putShort((short) sessionId);
			macInput.put(SecureConnection.xor(serverPublicKey, 0, publicKey, 0, SecureConnection.keyLength));

			final byte[] verifyAgainst = cbcMacSimple(session.deviceAuthKey(), macInput.array(), 0,
					macInput.capacity());
			final boolean authenticated = Arrays.equals(mac.array(), verifyAgainst);
			if (!authenticated) {
				final String packet = toHex(Arrays.copyOfRange(data, offset - 6, offset - 6 + 0x38), " ");
				throw new KnxSecureException("authentication failed for session response " + packet);
			}
		}

		return new Object[] { sessionId, serverPublicKey };
	}

	byte[] newSessionAuth(final byte[] serverPublicKey) {
		final KNXnetIPHeader header = new KNXnetIPHeader(SecureConnection.SecureSessionAuth, 2 + SecureConnection.macSize);

		final ByteBuffer buffer = ByteBuffer.allocate(header.getTotalLength());
		buffer.put(header.toByteArray());
		buffer.putShort((short) session.user());

		final int msgLen = 6 + 2 + SecureConnection.keyLength;
		final ByteBuffer macInput = ByteBuffer.allocate(16 + 2 + msgLen);
		macInput.put(new byte[16]);
		macInput.put((byte) 0);
		macInput.put((byte) msgLen);
		macInput.put(buffer.array(), 0, buffer.position());
		macInput.put(SecureConnection.xor(serverPublicKey, 0, publicKey, 0, SecureConnection.keyLength));
		final byte[] mac = cbcMacSimple(session.userKey(), macInput.array(), 0, macInput.capacity());
		SecureConnection.encrypt(mac, 0, session.userKey(), SecureConnection.securityInfo(new byte[16], 8, 0xff00));

		buffer.put(mac);
		return buffer.array();
	}

	void sessionStatus(final byte[] packet, final KNXnetIPHeader containedHeader) throws KNXFormatException {
		final int status = TcpConnection.SecureSession.newChannelStatus(containedHeader, packet,
				containedHeader.getStructLength());
		logger.log(status == 0 ? TRACE : ERROR, "{0}: {1}", this,
				SecureConnection.statusMsg(status));
		quitSetupLoop();
		sessionStatus = status;
	}

	byte[] newSecurePacket(final byte[] knxipPacket) {
		return SecureConnection.newSecurePacket(sessionId, session.nextSendSeq(), session.serialNumber(), 0,
				knxipPacket, secretKey);
	}

	Object[] unwrap(final KNXnetIPHeader h, final byte[] data, final int offset) throws KNXFormatException {
		final Object[] fields = SecureConnection.unwrap(h, data, offset, secretKey);

		final int sid = (int) fields[0];
		if (sid != sessionId)
			throw new KnxSecureException("secure session mismatch: received ID " + sid + ", expected " + sessionId);

		final long seq = (long) fields[1];
		final var rcvSeq = session.nextReceiveSeq();
		if (seq < rcvSeq)
			throw new KnxSecureException("received secure packet with sequence " + seq + " < expected " + rcvSeq);

		final var sn = (SerialNumber) fields[2];
		final int tag = (int) fields[3];
		final byte[] knxipPacket = (byte[]) fields[4];
		logger.log(TRACE, "received {0} (session {1} seq {2} S/N {3} tag {4})", toHex(knxipPacket, " "), sid, seq, sn, tag);
		return new Object[] { fields[0], fields[1], sn, fields[3], fields[4] };
	}

	@Override
	public String toString() {
		return secureSymbol + " session " + sessionId + " (user " + session.user() + ")";
	}

	private void quitSetupLoop() { setupLoop.quit(); }

	private byte[] cbcMacSimple(final Key secretKey, final byte[] data, final int offset, final int length) {
		final byte[] exact = Arrays.copyOfRange(data, offset, offset + length);
		logger.log(TRACE, "authenticating (length {0}): {1}", length, toHex(exact, " "));

		try {
			final Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			final IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

			final byte[] padded = Arrays.copyOfRange(exact, 0, (length + 15) / 16 * 16);
			final byte[] result = cipher.doFinal(padded);
			final byte[] mac = Arrays.copyOfRange(result, result.length - SecureConnection.macSize, result.length);
			return mac;
		}
		catch (final GeneralSecurityException e) {
			throw new KnxSecureException("calculating CBC-MAC of " + toHex(exact, " "), e);
		}
	}
}
