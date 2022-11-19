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

package tuwien.auto.calimero;

import static java.lang.System.Logger.Level.WARNING;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger;

import tuwien.auto.calimero.log.LogService;

/**
 * Creates, extracts and decodes information of protocol data units.
 * <p>
 * The methods focus on transport layer and application layer data units.
 *
 * @author B. Malinowsky
 */
public final class DataUnitBuilder
{
	/** Name of the log service used by data-unit builder methods. */
	public static final String LOG_SERVICE = "Data-unit builder";

	private static final Logger logger = LogService.getLogger(LOG_SERVICE);

	private static final int T_DATA_CONNECTED = 0x40;
	private static final int T_CONNECT = 0x80;
	private static final int T_DISCONNECT = 0x81;
	private static final int T_ACK = 0xC2;
	private static final int T_NAK = 0xC3;

	private DataUnitBuilder() {}

	/**
	 * Returns the application layer service of a given protocol data unit.
	 *
	 * @param apdu application layer protocol data unit, requires {@code apdu.length} &gt; 1
	 * @return APDU service code
	 */
	public static int getAPDUService(final byte[] apdu)
	{
		if (apdu.length < 2)
			throw new KNXIllegalArgumentException("getting APDU service from [0x" + toHex(apdu, "")
					+ "], APCI length < 2");
		// high 4 bits of APCI
		final int apci4 = (apdu[0] & 0x03) << 2 | (apdu[1] & 0xC0) >> 6;
		// lowest 6 bits of APCI
		final int apci6 = apdu[1] & 0x3f;
		// group value codes
		// group read
		if (apci4 == 0) {
			if (apci6 == 0)
				return 0;
		}
		// group response
		else if (apci4 == 1)
			return 0x40;
		// group write
		else if (apci4 == 2)
			return 0x80;
		// individual address codes
		else if (apci4 == 3 || apci4 == 4 || apci4 == 5) {
			if (apci6 == 0)
				return apci4 << 6;
		}
		// ADC read code
		else if (apci4 == 6)
			return apci4 << 6;
		else if (apci4 == 7) {
			// extended memory r/w services use the same 4 MSB as the ADC response code
			if (apdu.length > 5 || apci6 > 0x30)
				return apci4 << 6 | apci6;
			// ADC response code
			return apci4 << 6;
		}
		// memory codes
		else if (apci4 == 8 || apci4 == 9 || apci4 == 10)
			return apci4 << 6;
		// master reset uses same apci as restart, but with bit flags for restart type and response
		else if (apci4 == 14 && (apci6 == 1 || apci6 == 0b100001))
			return apci4 << 6;
		// the rest
		else
			return apci4 << 6 | apci6;
		// unknown codes
		final int code = apci4 << 6 | apci6;
		logger.log(WARNING, "unknown APCI service code 0x" + Integer.toHexString(code));
		return code;
	}

	/**
	 * Returns the transport layer service of a given protocol data unit.
	 *
	 * @param tpdu transport layer protocol data unit
	 * @return TPDU service code
	 */
	public static int getTPDUService(final byte[] tpdu)
	{
		final int ctrl = tpdu[0] & 0xff;
		if ((ctrl & 0xFC) == 0)
			return 0;
		// 0x04 is tag_group service code, not used by us
		if ((ctrl & 0xFC) == 0x04)
			return 0x04;
		if ((ctrl & 0xC0) == 0x40)
			return T_DATA_CONNECTED;
		if (ctrl == T_CONNECT)
			return T_CONNECT;
		if (ctrl == T_DISCONNECT)
			return T_DISCONNECT;
		if ((ctrl & 0xC3) == T_ACK)
			return T_ACK;
		if ((ctrl & 0xC3) == T_NAK)
			return T_NAK;
		logger.log(WARNING, "unknown TPCI service code 0x" + Integer.toHexString(ctrl));
		return ctrl;
	}

	/**
	 * Creates an application layer protocol data unit out of a service code and a service data
	 * unit.
	 * <p>
	 * The transport layer bits in the first byte (TL / AL control field) are set 0. For creating a
	 * length-optimized (compact) APDU, refer to {@link #createLengthOptimizedAPDU(int, byte[])}.
	 *
	 * @param service application layer service code
	 * @param asdu application layer service data unit, {@code asdu.length} &lt; 255
	 * @return APDU as byte array
	 */
	public static byte[] createAPDU(final int service, final byte... asdu)
	{
		if (asdu.length > 254)
			throw new KNXIllegalArgumentException("ASDU length exceeds maximum of 254 bytes");
		final byte[] apdu = new byte[2 + asdu.length];
		apdu[0] = (byte) ((service >> 8) & 0x03);
		apdu[1] |= (byte) service;
		for (int i = 0; i < asdu.length; ++i)
			apdu[i + 2] = asdu[i];
		return apdu;
	}

	/**
	 * Creates a length-optimized application layer protocol data unit out of a service
	 * code and a service data unit.
	 * <p>
	 * The transport layer bits in the first byte (TL / AL control field) are set 0. If the compact
	 * APDU shall not contain any ASDU information, {@code asdu} can be left {@code null}.
	 *
	 * @param service application layer service code
	 * @param asdu application layer service data unit, {@code asdu.length} &lt; 255
	 * @return APDU as byte array
	 */
	public static byte[] createLengthOptimizedAPDU(final int service, final byte... asdu)
	{
		final byte[] apdu = new byte[(asdu != null && asdu.length > 0) ? 1 + asdu.length : 2];
		if (apdu.length > 255)
			throw new KNXIllegalArgumentException("APDU length exceeds maximum of 255 bytes");
		apdu[0] = (byte) ((service >> 8) & 0x03);
		apdu[1] = (byte) service;
		if (asdu != null && asdu.length > 0) {
			// maximum of 6 bits in asdu[0] are valid
			apdu[1] |= asdu[0] & 0x3F;
			for (int i = 1; i < asdu.length; ++i)
				apdu[i + 1] = asdu[i];
		}
		return apdu;
	}

	/**
	 * Returns a copy of the ASDU contained in the supplied APDU.
	 * <p>
	 * The application layer service data unit (ASDU) is the APDU with the application
	 * layer service code removed.
	 *
	 * @param apdu application layer protocol data unit for which to get the ASDU
	 * @return the ASDU as byte array
	 */
	public static byte[] extractASDU(final byte[] apdu)
	{
		final int svc = getAPDUService(apdu);
		int offset = 2;
		int mask = 0xff;
		// 0x40 A_GroupValue_Response-PDU
		// 0x80 A_GroupValue_Write-PDU
		if (svc == 0x40 || svc == 0x80) {
			// only adjust for optimized read.res and write
			if (apdu.length <= 2) {
				offset = 1;
				mask = 0x3f;
			}
		}
		// 0x0180 A_ADC_Read-PDU
		// 0x01C0 A_ADC_Response-PDU
		else if (svc == 0x0180 || svc == 0x01C0) {
			offset = 1;
			mask = 0x3f;
		}
		// 0x0200 A_Memory_Read-PDU
		// 0x0240 A_Memory_Response-PDU
		// 0x0280 A_Memory_Write-PDU
		else if (svc == 0x0200 || svc == 0x0240 || svc == 0x0280) {
			offset = 1;
			// masks the number of bytes field,
			// the field size was increased to 6 bits in 03/03/07 2007
			mask = 0x3f;
		}
		// 0x300 A_DeviceDescriptor_Read-PDU
		// 0x340 A_DeviceDescriptor_Response-PDU
		else if (svc == 0x300 || svc == 0x340) {
			offset = 1;
			// we mask the descriptor type
			mask = 0x3f;
		}
		// 0x100 A_IndividualAddress_Read-PDU
		// 0x140 A_IndividualAddress_Response-PDU
		else if (svc == 0x100 || svc == 0x140) {
			offset = 1;
			// we mask the lower 6 bits that need to be 0
			mask = 0x3f;
		}
		// 0x380 A_Restart-PDU
		else if (svc == 0x380) {
			offset = 1;
			// we mask the response bit and restart type bit
			mask = 0x3f;
		}
		final byte[] asdu = new byte[apdu.length - offset];
		for (int i = 0; i < asdu.length; ++i)
			asdu[i] = apdu[offset + i];

		// some ASDUs have length 0, e.g., DoA.read
		if (asdu.length > 0)
			asdu[0] &= mask;
		return asdu;
	}

	/**
	 * Decodes a protocol data unit into a textual representation.
	 * <p>
	 * Currently, the transport layer protocol control information (TPCI) and the
	 * application layer protocol control information (APCI) is decoded. Decoding might be
	 * extended in the future.<br>
	 * The optional KNX destination address helps to determine the exact transport layer
	 * service.
	 *
	 * @param tpdu transport layer protocol data unit to decode
	 * @param dst KNX destination address belonging to the TPDU, might be
	 *        {@code null}
	 * @return textual representation of control information in the TPDU
	 */
	public static String decode(final byte[] tpdu, final KNXAddress dst)
	{
		if (tpdu.length < 1)
			throw new KNXIllegalArgumentException("TPDU length too short");
		final String s = decodeTPCI(tpdu[0] & 0xff, dst);
		if (tpdu.length > 1)
			return s + ", " + decodeAPCI(getAPDUService(tpdu));
		return s;
	}

	/**
	 * Decodes a transport layer protocol control information into a textual
	 * representation.
	 *
	 * @param tpci transport layer protocol control information
	 * @param dst KNX destination address belonging to the tpci, might be
	 *        {@code null}
	 * @return textual representation of TPCI
	 */
	public static String decodeTPCI(final int tpci, final KNXAddress dst)
	{
		final int ctrl = tpci & 0xff;
		if ((ctrl & 0xFC) == 0) {
			if (dst == null)
				return "T_Broadcast/group/ind";
			if (dst.getRawAddress() == 0)
				return "T_Broadcast";
			if (dst instanceof GroupAddress)
				return "T_Group";
			return "T-individual";
		}
		if ((ctrl & 0xC0) == 0x40)
			return "T_Connected seq " + (ctrl >> 2 & 0xF);
		if (ctrl == T_CONNECT)
			return "T_Connect";
		if (ctrl == T_DISCONNECT)
			return "T_Disconnect";
		if ((ctrl & 0xC3) == T_ACK)
			return "T_Ack seq " + (ctrl >> 2 & 0xF);
		if ((ctrl & 0xC3) == T_NAK)
			return "T_Nak seq " + (ctrl >> 2 & 0xF);
		if ((ctrl & 0xfc) == 0x04)
			return "T_TagGroup";
		return "unknown TPCI";
	}

	/**
	 * Decodes an application layer protocol control information into a textual
	 * representation.
	 *
	 * @param apci application layer protocol control information
	 * @return textual representation of APCI
	 */
	public static String decodeAPCI(final int apci)
	{
		switch (apci) {
		case 0x00:
			return "A_Group.read";
		case 0x40:
			return "A_Group.response";
		case 0x80:
			return "A_Group.write";
		case 0x0180:
			return "A_ADC.read";
		case 0x01C0:
			return "A_ADC.response";
		case 0x03D1:
			return "A_Authorize.read";
		case 0x03D2:
			return "A_Authorize.response";
		case 0x3E0:
			return "A_Domain.write";
		case 0x3E1:
			return "A_Domain.read";
		case 0x3E2:
			return "A_Domain.response";
		case 0x3E3:
			return "A_Domain-selective.read";
		case 0x0100:
			return "A_IndAddr.read";
		case 0x0140:
			return "A_IndAddr.response";
		case 0xC0:
			return "A_IndAddr.write";
		case 0x03DC:
			return "A_IndAddr-S/N.read";
		case 0x03DD:
			return "A_IndAddr-S/N.response";
		case 0x03DE:
			return "A_IndAddr-S/N.write";
		case 0x300:
			return "A_Device-desc.read";
		case 0x340:
			return "A_Device-desc.response";
		case 0x03D3:
			return "A_Key.write";
		case 0x03D4:
			return "A_Key.response";
		case 0x0200:
			return "A_Memory.read";
		case 0x0240:
			return "A_Memory.response";
		case 0x0280:
			return "A_Memory.write";
		case 0x03D8:
			return "A_Property-desc.read";
		case 0x03D9:
			return "A_Property-desc.response";
		case 0x03D5:
			return "A_Property.read";
		case 0x03D6:
			return "A_Property.response";
		case 0x03D7:
			return "A_Property.write";
		case 0x0380:
			return "A_Restart";
		case 0b1111011010:
			return "A_NetworkParameter.read";
		case 0b1111011011:
			return "A_NetworkParameter.response";
		case 0b1111100100:
			return "A_NetworkParameter.write";
		case 0b1111101000:
			return "A_GroupPropValue.read";
		case 0b1111101001:
			return "A_GroupPropValue.response";
		case 0b1111101010:
			return "A_GroupPropValue.write";
		case 0b1111101011:
			return "A_GroupPropValue.info";
		case 0b0111111011:
			return "A_MemoryExtended.write";
		case 0b0111111100:
			return "A_MemoryExtended.write-response";
		case 0b0111111101:
			return "A_MemoryExtended.read";
		case 0b0111111110:
			return "A_MemoryExtended.read-response";
		case 0b0111001000:
			return "A_SystemNetworkParameter.read";
		case 0b0111001001:
			return "A_SystemNetworkParameter.response";
		case 0b0111001010:
			return "A_SystemNetworkParameter.write";
		case 0b1111101100:
			return "A_DoA-S/N.read";
		case 0b1111101101:
			return "A_DoA-S/N.response";
		case 0b1111101110:
			return "A_DoA-S/N.write";
		case 0b1011000111:
			return "A_FunctionPropertyCommand";
		case 0b1011001000:
			return "A_FunctionPropertyState.read";
		case 0b1011001001:
			return "A_FunctionPropertyState.response";
		// services for extended interface object addressing
		case 0b0111001100:
			return "A_PropertyExtValue.read";
		case 0b0111001101:
			return "A_PropertyExtValue.response";
		case 0b0111001110:
			return "A_PropertyExtValue.write";
		case 0b0111001111:
			return "A_PropertyExtValue.write-response";
		case 0b0111010000:
			return "A_PropertyExtValue.write-uncon";
		case 0b0111010001:
			return "A_PropertyExtValue.info";
		case 0b0111010010:
			return "A_PropertyExtDescription.read";
		case 0b0111010011:
			return "A_PropertyExtDescription.response";
		case 0b0111010100:
			return "A_FunctionPropertyExtCommand";
		case 0b0111010101:
			return "A_FunctionPropertyExtState.read";
		case 0b0111010110:
			return "A_FunctionPropertyExtState.response";

		case 0x3f1:
			return "S-A_Data";
		default:
			return "APCI 0x" + Integer.toHexString(apci);
		}
	}

	/**
	 * Returns the content of {@code data} as unsigned bytes in hexadecimal string
	 * representation.
	 * <p>
	 * This method does not add hexadecimal prefixes (like 0x).
	 *
	 * @param data data array to format
	 * @param sep separator to insert between 2 formatted data bytes, {@code null}
	 *        or "" for no gap between byte tokens
	 * @return an unsigned hexadecimal string of data
	 */
	public static String toHex(final byte[] data, final String sep)
	{
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < data.length; ++i) {
			final int no = data[i] & 0xff;
			if (no < 0x10)
				sb.append('0');
			sb.append(Integer.toHexString(no));
			if (sep != null && i < data.length - 1)
				sb.append(sep);
		}
		return sb.toString();
	}

	/**
	 * Parses {@code hex} as unsigned hexadecimal value into a byte array. Input containing space characters
	 * (ASCII code 0x20) is treated as if the spaces are non-existent.
	 *
	 * @param hex hexadecimal string representation, without any hexadecimal prefixes (like 0x); {@code hex.length}
	 *        (ignoring spaces) has to be even
	 * @return byte array containing the parsed value, with array length equal to {@code hex.length / 2} (not
	 * considering any spaces)
	 */
	public static byte[] fromHex(final String hex) {
		final String s = hex.replace(" ", "");
		final int len = s.length();
		final byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2)
			data[i / 2] = (byte) ((digit(s.charAt(i)) << 4) + digit(s.charAt(i + 1)));
		return data;
	}

	private static int digit(final char c) {
		final int digit = Character.digit(c, 16);
		if (digit == -1)
			throw new KNXIllegalArgumentException("invalid hex char '" + c + "'");
		return digit;
	}

	public static final class Builder {
		private final ByteArrayOutputStream baos = new ByteArrayOutputStream();

		private Builder() {}

		public Builder put(final int oneByte) { baos.write(oneByte); return this; }

		public Builder putShort(final int twoBytes) { return put(twoBytes >> 8).put(twoBytes); }

		public Builder put(final byte[] bytes) { baos.writeBytes(bytes); return this; }

		public byte[] build() { return baos.toByteArray(); }
	}

	public static Builder apdu(final int service) { return new Builder().putShort(service & 0x03ff); }
}
