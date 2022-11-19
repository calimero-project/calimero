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

package tuwien.auto.calimero.knxnetip.util;

import static java.lang.System.Logger.Level.WARNING;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.knxnetip.KNXnetIPDevMgmt;
import tuwien.auto.calimero.knxnetip.KNXnetIPTunnel;
import tuwien.auto.calimero.log.LogService;

/**
 * Package private container class acting as common base for connection request
 * information (CRI) and connection response data (CRD).<br>
 * It represents either a CRI or a CRD structure.
 */
class CRBase
{
	static final Logger logger = LogService.getLogger("KNXnet/IP service");

	byte[] opt;
	private final int connType;
	private final int length;

	/**
	 * Creates a new CR out of a byte array.
	 *
	 * @param data byte array containing a CRI or CRD structure
	 * @param offset start offset
	 * @throws KNXFormatException on invalid structure
	 */
	CRBase(final byte[] data, final int offset) throws KNXFormatException
	{
		int i = offset;
		length = data[i++] & 0xFF;
		connType = data[i++] & 0xFF;
		if (length > data.length - offset)
			throw new KNXFormatException("structure length bigger than buffer", length);
		opt = new byte[length - 2];
		for (int k = 0; k < length - 2; ++i, ++k)
			opt[k] = data[i];
	}

	/**
	 * Creates a new CR for the given connection type.
	 * <p>
	 * The array of {@code optionalData} is not copied for internal storage. No
	 * additional checks regarding content are done.
	 *
	 * @param connectionType connection type the CR is used for
	 * @param optionalData byte array containing optional host protocol independent and
	 *        dependent data, this information is located starting at offset 2 in the CR
	 *        structure, {@code optionalData.length} &lt; 254
	 */
	CRBase(final int connectionType, final byte[] optionalData)
	{
		if (connectionType < 0 || connectionType > 0xff)
			throw new KNXIllegalArgumentException("connection type out of range [0..255]");
		length = 2 + optionalData.length;
		if (length > 0xff)
			throw new KNXIllegalArgumentException("optional data exceeds maximum length");
		connType = connectionType;
		opt = optionalData;
	}

	// returns a CRI or CRD depending on request
	static CRBase create(final boolean request, final byte[] data, final int offset)
		throws KNXFormatException
	{
		if (data.length - offset < 2)
			throw new KNXFormatException("buffer too short for " + (request ? "CRI" : "CRD"));
		final int type = data[offset + 1] & 0xff;
		if (type == KNXnetIPTunnel.TUNNEL_CONNECTION)
			return request ? (CRBase) new TunnelCRI(data, offset) : new TunnelCRD(data, offset);
		if (type != KNXnetIPDevMgmt.DEVICE_MGMT_CONNECTION && type != 0xf0)
			logger.log(WARNING, "unknown connection type 0x" + Integer.toHexString(type) + ", create default CRI/CRD");
		return request ? (CRBase) new CRI(data, offset) : new CRD(data, offset);
	}

	// returns a CRI or CRD depending on request
	static CRBase create(final boolean request, final int type, final byte[] data)
	{
		final byte[] opt = data;
		if (type == KNXnetIPTunnel.TUNNEL_CONNECTION)
			return request ? (CRBase) new TunnelCRI(opt) : new TunnelCRD(opt);
		if (type != KNXnetIPDevMgmt.DEVICE_MGMT_CONNECTION && type != 0xf0)
			logger.log(WARNING, "unknown connection type 0x" + Integer.toHexString(type) + ", create default CRI/CRD");
		return request ? (CRBase) new CRI(type, opt.clone()) : new CRD(type, opt.clone());
	}

	/**
	 * Returns the used connection type code.
	 *
	 * @return connection type as unsigned byte
	 */
	public final int getConnectionType()
	{
		return connType;
	}

	/**
	 * Returns a copy of the optional data field, starting at offset 2 in the CR structure.
	 *
	 * @return byte array with optional data
	 */
	public final byte[] getOptionalData()
	{
		return opt.clone();
	}

	/**
	 * Returns the structure length of this CR in bytes.
	 *
	 * @return structure length as unsigned byte
	 */
	public final int getStructLength()
	{
		return length;
	}

	/**
	 * Returns a textual representation of the connection type, length and optional data.
	 *
	 * @return a string representation of this object
	 */
	@Override
	public String toString()
	{
		return "connection type " + connType + " length " + length + " data "
				+ (opt.length == 0 ? "-" : DataUnitBuilder.toHex(opt, " "));
	}

	/**
	 * Returns the byte representation of the whole CR structure.
	 *
	 * @return byte array containing structure
	 */
	public byte[] toByteArray()
	{
		final ByteArrayOutputStream os = new ByteArrayOutputStream();
		os.write(length);
		os.write(connType);
		os.write(opt, 0, opt.length);
		return os.toByteArray();
	}
}
