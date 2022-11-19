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

package tuwien.auto.calimero.knxnetip.servicetype;

import static tuwien.auto.calimero.ReturnCode.Success;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.util.Optional;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.ReturnCode;

/**
 * Provides minimal management services over a KNXnet/IP tunneling connection (similar to the KNX USB Bus Access Server
 * Feature protocol).
 */
public final class TunnelingFeature implements tuwien.auto.calimero.ServiceType {

	public enum InterfaceFeature {
		SupportedEmiTypes,
		DeviceDescriptorType0,
		ConnectionStatus,
		Manufacturer,
		ActiveEmiType,
		IndividualAddress,
		MaxApduLength,
		EnableFeatureInfoService;

		int id() { return ordinal() + 1; }

		@Override
		public String toString() { return friendly(); }

		private String friendly() { return name().replaceAll("(\\p{Lower})\\B([A-Z0])", "$1 $2").toLowerCase(); }
	}

	/**
	 * Creates a new tunneling feature-get service.
	 *
	 * @param featureId the requested interface feature
	 * @return new tunneling feature-get service
	 */
	public static TunnelingFeature newGet(final InterfaceFeature featureId) {
		return new TunnelingFeature(KNXnetIPHeader.TunnelingFeatureGet, featureId, Success);
	}

	/**
	 * Creates a new tunneling feature-response service.
	 *
	 * @param featureId interface feature to respond to
	 * @param result result of processing the corresponding tunneling feature-get/set service
	 * @param featureValue feature value sent with a response (optional, depdending on {@code result})
	 * @return new tunneling feature-response service
	 */
	public static TunnelingFeature newResponse(final InterfaceFeature featureId, final ReturnCode result,
			final byte... featureValue) {
		return new TunnelingFeature(KNXnetIPHeader.TunnelingFeatureResponse, featureId, result, featureValue);
	}

	/**
	 * Creates a new tunneling feature-set service.
	 *
	 * @param featureId interface feature which value should be set
	 * @param featureValue feature value to set
	 * @return new tunneling feature-set service
	 */
	public static TunnelingFeature newSet(final InterfaceFeature featureId, final byte... featureValue) {
		return new TunnelingFeature(KNXnetIPHeader.TunnelingFeatureSet, featureId, Success, featureValue);
	}

	/**
	 * Creates a new tunneling feature-info service.
	 *
	 * @param featureId interface feature which should be announced
	 * @param featureValue feature value to announce
	 * @return new tunneling feature-info service
	 */
	public static TunnelingFeature newInfo(final InterfaceFeature featureId, final byte... featureValue) {
		return new TunnelingFeature(KNXnetIPHeader.TunnelingFeatureInfo, featureId, Success, featureValue);
	}

	/**
	 * Creates a new tunneling feature service by parsing the supplied byte buffer containing a tunneling feature
	 * service.
	 *
	 * @param svcType tunneling feature service type
	 * @param buffer byte buffer positioned at the start of the feature service (within a KNXnet/IP tunneling datagram)
	 * @return a tunneling feature service
	 * @throws KNXFormatException if the structure is invalid or an invalid tunneling feature service was found
	 */
	public static TunnelingFeature from(final int svcType, final ByteBuffer buffer) throws KNXFormatException {
		return new TunnelingFeature(svcType, buffer);
	}


	private static final int MinServiceSize = 2;

	private final int svcType;
	private final InterfaceFeature featureId;
	private final ReturnCode status;
	private final byte[] data;

	private TunnelingFeature(final int serviceType, final InterfaceFeature featureId, final ReturnCode status,
			final byte... data) {
		this.svcType = serviceType;
		this.featureId = featureId;
		this.status = status;
		this.data = data.clone();
		validateFeatureValueLength();
	}

	private TunnelingFeature(final int svcType, final ByteBuffer bb) throws KNXFormatException {
		if (bb.remaining() < MinServiceSize)
			throw new KNXFormatException("buffer too short for tunneling feature service");

		final int id = bb.get() & 0xff;
		if (id > InterfaceFeature.values().length)
			throw new KNXFormatException(ReturnCode.AddressVoid.description(), id);

		this.svcType = svcType;
		featureId = InterfaceFeature.values()[id - 1];
		status = ReturnCode.of(bb.get() & 0xff);
		if (status.code() > 0xf0)
			ServiceType.logger.log(Level.WARNING, "feature {0} responded with ''{1}''", featureId, status);
		data = new byte[bb.remaining()];
		bb.get(data);
		validateFeatureValueLength();
	}

	private void validateFeatureValueLength() {
		final int length;
		if (svcType == KNXnetIPHeader.TunnelingFeatureGet)
			length = 0;
		else {
			switch (featureId) {
			case SupportedEmiTypes:
			case DeviceDescriptorType0:
			case Manufacturer:
			case IndividualAddress:
			case MaxApduLength:
				length = 2;
				break;
			case ConnectionStatus:
			case ActiveEmiType:
			case EnableFeatureInfoService:
				length = 1;
				break;
			default:
				throw new IllegalStateException();
			}
		}
		if (data.length != length)
			throw new KNXIllegalArgumentException(String.format("%s %s value %s with invalid length %d, expected %d",
					KNXnetIPHeader.getSvcName(svcType), featureId, DataUnitBuilder.toHex(data, ""), data.length, length));
	}

	public int type() { return svcType; }

	public InterfaceFeature featureId() {
		return featureId;
	}

	public Optional<byte[]> featureValue() {
		return data.length > 0 ? Optional.of(data) : Optional.empty();
	}

	public ReturnCode status() {
		return status;
	}

	@Override
	public String toString() {
		final var s = status == Success ? DataUnitBuilder.toHex(featureValue().orElse(new byte[0]), "") : status;
		return String.format("%s %s %s", KNXnetIPHeader.getSvcName(svcType), featureId, s);
	}

	@Override
	public int length() {
		return MinServiceSize + data.length;
	}

	@Override
	public byte[] toByteArray() {
		final var os = new ByteArrayOutputStream();
		os.write(featureId.id());
		os.write(status.code());
		os.write(data, 0, data.length);
		return os.toByteArray();
	}
}
