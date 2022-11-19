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

package tuwien.auto.calimero.knxnetip.servicetype;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger.Level;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.knxnetip.util.AdditionalDeviceDib;
import tuwien.auto.calimero.knxnetip.util.DIB;
import tuwien.auto.calimero.knxnetip.util.DeviceDIB;
import tuwien.auto.calimero.knxnetip.util.IPConfigDIB;
import tuwien.auto.calimero.knxnetip.util.IPCurrentConfigDIB;
import tuwien.auto.calimero.knxnetip.util.KnxAddressesDIB;
import tuwien.auto.calimero.knxnetip.util.ManufacturerDIB;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB;
import tuwien.auto.calimero.knxnetip.util.TunnelingDib;

/**
 * Represents a description response.
 * <p>
 * Such response is sent by a server in reply to a description request from a client.<br>
 * A response contains various description information blocks (DIBs), mandatory being a Device DIB
 * and a Supported Service Families DIB. Optionally, the response might contain additional DIBs with
 * other information. Each DIB can at most occur once, the following DIBs are recognized (others are ignored):
 * <ul>
 * <li>{@link DeviceDIB}</li>
 * <li>{@link ServiceFamiliesDIB}</li>
 * <li>{@link IPConfigDIB}</li>
 * <li>{@link IPCurrentConfigDIB}</li>
 * <li>{@link KnxAddressesDIB}</li>
 * <li>{@link ManufacturerDIB}</li>
 * <li>{@link TunnelingDib}</li>
 * <li>{@link AdditionalDeviceDib}</li>
 * </ul>
 * <p>
 * Objects of this type are immutable.
 *
 * @author B. Malinowsky
 * @see tuwien.auto.calimero.knxnetip.servicetype.DescriptionRequest
 */
public class DescriptionResponse extends ServiceType
{
	private final Map<Integer, DIB> dibs = new HashMap<>();

	/**
	 * Creates a new description response out of a byte array.
	 *
	 * @param data byte array containing a description response structure
	 * @param offset start offset of response in {@code data}
	 * @param length usable length of {@code data}, {@code 0 < length ≤ (data.length - offset)}
	 * @throws KNXFormatException if no description response was found or invalid structure of DIBs carried in the
	 *         response
	 */
	public DescriptionResponse(final byte[] data, final int offset, final int length) throws KNXFormatException
	{
		super(KNXnetIPHeader.DESCRIPTION_RES);

		int i = offset;
		while (i + 1 < offset + length) {
			final int size = data[i] & 0xff;
			// skip any remaining DIBs on invalid size, as we cannot advance our index
			if (size == 0)
				break;
			final int type = data[i + 1] & 0xff;
			if (dibs.containsKey(type))
				throw new KNXFormatException("response contains duplicate DIB type", type);
			final DIB dib = parseDib(type, data, i, size);
			if (dib == null)
				logger.log(Level.WARNING, "skip unknown DIB in response of type {0} and size {1}", type, size);
			else
				dibs.put(type, dib);
			i += size;
		}
	}

	private static DIB parseDib(final int type, final byte[] data, final int offset, final int size)
		throws KNXFormatException {
		switch (type) {
		case DIB.DEVICE_INFO: return new DeviceDIB(data, offset);
		case DIB.SUPP_SVC_FAMILIES: return new ServiceFamiliesDIB(data, offset);
		case DIB.IP_CONFIG: return new IPConfigDIB(data, offset);
		case DIB.IP_CURRENT_CONFIG: return new IPCurrentConfigDIB(data, offset);
		case DIB.KNX_ADDRESSES: return new KnxAddressesDIB(data, offset);
		case DIB.MFR_DATA: return new ManufacturerDIB(data, offset);
		case DIB.SecureServiceFamilies: return new ServiceFamiliesDIB(data, offset);
		case DIB.TunnelingInfo: return new TunnelingDib(data, offset, size);
		case DIB.AdditionalDeviceInfo: return new AdditionalDeviceDib(data, offset, size);
		}
		return null;
	}

	/**
	 * Creates a new description response containing a device DIB, a supported service families DIB, and optional other
	 * DIBs.
	 *
	 * @param device device description
	 * @param svcFamilies supported service families
	 * @param additionalDibs optional DIBs to add to the response
	 */
	public DescriptionResponse(final DeviceDIB device, final ServiceFamiliesDIB svcFamilies, final DIB... additionalDibs)
	{
		super(KNXnetIPHeader.DESCRIPTION_RES);

		dibs.put(device.getDescTypeCode(), device);
		dibs.put(svcFamilies.getDescTypeCode(), svcFamilies);
		for (final DIB dib : additionalDibs) {
			final int type = dib.getDescTypeCode();
			if (dibs.containsKey(type))
				throw new KNXIllegalArgumentException("response contains duplicate DIB type " + type);
			dibs.put(type, dib);
		}
	}

	DescriptionResponse(final List<DIB> dibs) {
		super(KNXnetIPHeader.DESCRIPTION_RES);

		for (final DIB dib : dibs) {
			final int type = dib.getDescTypeCode();
			if (this.dibs.containsKey(type))
				throw new KNXIllegalArgumentException("response contains duplicate DIB type " + type);
			this.dibs.put(type, dib);
		}
	}

	/**
	 * @return the complete description information contained in this response, as list of
	 *         description information blocks (DIBs)
	 */
	public final List<DIB> getDescription()
	{
		return Arrays.asList(dibs.values().toArray(new DIB[dibs.size()]));
	}

	/**
	 * Returns the device description information block contained in the response.
	 *
	 * @return a device DIB
	 */
	public final DeviceDIB getDevice()
	{
		return (DeviceDIB) dibs.get(DIB.DEVICE_INFO);
	}

	/**
	 * Returns the supported service families description information block.
	 *
	 * @return a DIB with the supported service families
	 */
	public final ServiceFamiliesDIB getServiceFamilies()
	{
		return (ServiceFamiliesDIB) dibs.get(DIB.SUPP_SVC_FAMILIES);
	}

	@Override
	public boolean equals(final Object obj)
	{
		if (this == obj)
			return true;
		if (!(obj instanceof DescriptionResponse))
			return false;
		final DescriptionResponse other = (DescriptionResponse) obj;
		return dibs.equals(other.dibs);
	}

	@Override
	public int hashCode()
	{
		final int prime = 17;
		return prime * dibs.hashCode();
	}

	@Override
	public String toString()
	{
		return getDescription().stream().map(Object::toString).collect(Collectors.joining(", "));
	}

	@Override
	int getStructLength()
	{
		int len = 0;
		for (final Iterator<DIB> i = getDescription().iterator(); i.hasNext();)
			len += i.next().getStructLength();
		return len;
	}

	@Override
	byte[] toByteArray(final ByteArrayOutputStream os)
	{
		for (final Iterator<DIB> i = getDescription().iterator(); i.hasNext();) {
			final byte[] bytes = i.next().toByteArray();
			os.write(bytes, 0, bytes.length);
		}
		return os.toByteArray();
	}
}
