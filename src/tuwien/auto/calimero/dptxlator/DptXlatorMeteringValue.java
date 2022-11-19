/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2017, 2022 B. Malinowsky

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

package tuwien.auto.calimero.dptxlator;

import static java.lang.System.Logger.Level.ERROR;

import java.lang.System.Logger.Level;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;

/**
 * Translator for KNX DPTs with main number 229, type <b>V32 N8 Z8</b>. It provides the DPT for M-Bus metering values in
 * the following application domains:
 * <ul>
 * <li>Common use</li>
 * </ul>
 * The KNX data type width is 6 bytes. The default return value after creation is the <i>dimensionless counter</i> with
 * value 0.
 * <p>
 * In value methods expecting string items, an item is formatted as metering value with (optional) unit, e.g., "210.35
 * l/h". The unit is used to assign the M-Bus value information field (VIF) coding, i.e., in the case of "l/h" the
 * encoding would be "volume flow" in m³/h. A metering value without unit is encoded as <i>dimensionless counter</i>
 * (M-Bus VIFE coding {@code 0b10111010}).
 */
@SuppressWarnings("checkstyle:javadocvariable")
public class DptXlatorMeteringValue extends DPTXlator
{
//	NYI method for setting counter value with status
//	NYI publish the units (constants/enum) that are used to detect the coding

	public static final DPT DptMeteringValue = new DPT("229.001", "Metering Value", Integer.toString(Integer.MIN_VALUE),
			Integer.toString(Integer.MAX_VALUE));

	private static final Map<String, DPT> types = new HashMap<>();

	private static final int dimensionlessCounter = 0b10111010;
	private final DptXlator8BitSet status = new DptXlator8BitSet(DptXlator8BitSet.DptGeneralStatus);
	private final DPTXlator4ByteSigned cv = new DPTXlator4ByteSigned(DPTXlator4ByteSigned.DPT_COUNT);

	private String description;
	private String unit;
	private int expUnitAdjustment;

	static {
		types.put(DptMeteringValue.getID(), DptMeteringValue);
	}

	/**
	 * Creates a translator for the given datapoint type.
	 *
	 * @param dpt the requested datapoint type
	 * @throws KNXFormatException on not supported or not available DPT
	 */
	public DptXlatorMeteringValue(final DPT dpt) throws KNXFormatException
	{
		this(dpt.getID());
	}

	/**
	 * Creates a translator for the given datapoint type ID.
	 *
	 * @param dptId datapoint type ID
	 * @throws KNXFormatException on wrong formatted or unsupported {@code dptId}
	 */
	public DptXlatorMeteringValue(final String dptId) throws KNXFormatException
	{
		super(6);
		setTypeID(types, dptId);
		data[4] = dimensionlessCounter;
	}

	@Override
	public String getValue()
	{
		return textOf(0);
	}

	/**
	 * Sets one new translation item from a dimensionless counter value, replacing any old items.
	 *
	 * @param value dimensionless counter value
	 */
	// TODO method might not make much sense
	@Override
	public final void setValue(final double value)
	{
		expUnitAdjustment = 0;
		try {
			data = toDpt(dimensionlessCounter, value);
		}
		catch (final KNXFormatException e) {
			logger.log(ERROR, "{0} {1} coding {2} (value {3}) should alway have correct format", dpt.getID(),
					dpt.getDescription(), binary(dimensionlessCounter), value, e);
		}
	}

	/**
	 * Sets one new translation item from a metering value, replacing any old items.
	 *
	 * @param coding coding of {@code value}
	 * @param value metering value
	 * @throws KNXFormatException if value is out of range specified by the DPT
	 */
	public final void setValue(final int coding, final double value) throws KNXFormatException
	{
		expUnitAdjustment = 0;
		data = toDpt(coding, value);
	}

	public final DptXlator8BitSet status()
	{
		status.setData(new byte[] { (byte) data[5] });
		return status;
	}

	@Override
	public final double getNumericValue()
	{
		return fromDpt(0);
	}

	@Override
	public String[] getAllValues()
	{
		final String[] s = new String[data.length / typeSize];
		for (int i = 0; i < s.length; ++i)
			s[i] = textOf(i);
		return s;
	}

	@Override
	public final Map<String, DPT> getSubTypes()
	{
		return types;
	}

	@Override
	protected void toDPT(final String value, final short[] dst, final int index) throws KNXFormatException
	{
		// TODO the splitting into status/value/unit parts might be wrong for dimensionless counter values
		final String[] split = value.split(" ");
		final boolean hasUnit = split.length > 1;
		final String number = split[hasUnit ? split.length - 2 : 0];
		unit = hasUnit ? split[split.length - 1] : "";
		// XXX this only works with a unique (or no) unit, otherwise it's a guess at best
		final int coding = coding(unit);
		try {
			final short[] result = toDpt(coding, Double.parseDouble(number));
			final int offset = index * typeSize;
			for (int i = 0; i < result.length; i++)
				dst[offset + i] = result[i];
			// if we got any status info, parse it and set the status field
			if (split.length > 2) {
				final String[] statusPart = Arrays.copyOfRange(split, 0, split.length - 2);
				status.setValue(Arrays.asList(statusPart).stream().collect(Collectors.joining(" ")));
				dst[offset + 5] = (short) status.getNumericValue();
			}
		}
		catch (final NumberFormatException e) {
			throw newException("not a parsable number", number, e);
		}
	}

	/**
	 * @return all available subtypes of this translator
	 * @see DPTXlator#getSubTypesStatic()
	 */
	protected static Map<String, DPT> getSubTypesStatic()
	{
		return types;
	}

	private String textOf(final int index)
	{
		final int i = 6 * index;
		status.setData(new byte[] { (byte) data[i + 5] });
		final String s = status.getValue();
		return ((s.isEmpty() ? "" : s + ", ") + fromDpt(index) + appendUnit()).trim();
	}

	private String appendUnit()
	{
		return appendUnit && !unit.isEmpty() ? " " + unit : "";
	}

	private short[] toDpt(final int coding, final double value) throws KNXFormatException
	{
		final int exp = coding(coding);
		final double result = Math.pow(10, -exp + expUnitAdjustment) * value;
		final int counterValue = (int) result;
		final short status = 0;

		cv.setValue(counterValue);
		final byte[] data = cv.getData();

		return new short[] { ubyte(data[0]), ubyte(data[1]), ubyte(data[2]), ubyte(data[3]), (short) coding, status };
	}

	private double fromDpt(final int index)
	{
		final int i = 6 * index;
		cv.setData(new byte[] { (byte) data[i], (byte) data[i + 1], (byte) data[i + 2], (byte) data[i + 3] });

		final int coding = ubyte(data[i + 4]);
		try {
			final int exp = coding(coding);
			final double result = Math.pow(10, exp) * cv.getNumericValue();
			logger.log(Level.INFO, "{0} {1} ''{2}'' {3} (exp {4}) value {5} {6}", dpt.getID(), dpt.getDescription(),
					description, binary(coding), exp, result, unit);
			return result;
		}
		catch (final KNXFormatException e) {
			// TODO implementation assumes this does not happen (it could, because we don't validate knx data)
			logger.log(ERROR, "{0} {1} unsupported coding {2}", dpt.getID(), dpt.getDescription(), binary(coding));
			return cv.getNumericValue();
		}
	}

	// extracts exponent from coding
	private int coding(final int coding) throws KNXFormatException
	{
		if (coding < 0 || coding > 0xff)
			throw new KNXIllegalArgumentException("coding " + binary(coding) + " out of range [0..0xff]");

		final String desc;
		final String unit;
		int exp = 0;

		final int vifExtensionBit = 0b10000000;
		if ((coding & vifExtensionBit) == 0) {
			final int vifMask = 0b11111000;
			final int id = coding & vifMask;
			final int n = coding & ~vifMask;

			if (id == 0b00000000) { // 0.001 Wh to 10 000 Wh
				desc = "energy";
				unit = "Wh";
				exp = n - 3;
			}
			else if (id == 0b00001000) { // 0.001 kJ to 10 000 kJ
				desc = "energy";
				unit = "J";
				exp = n;
			}
			else if (id == 0b00010000) { // 0.001 l to 10000 l
				desc = "volume";
				unit = "m³";
				exp = n - 6;
			}
			else if (id == 0b00011000) { // 0.001 kg to 10 000 kg
				desc = "mass";
				unit = "kg";
				exp = n - 3;
			}
			else if (id == 0b00101000) { // 0.001 W to 10000 W
				desc = "power";
				unit = "W";
				exp = n - 3;
			}
			else if (id == 0b00110000) { // 0.001 kJ/h to 10 000 kJ/h
				desc = "power";
				unit = "J/h";
				exp = n;
			}
			else if (id == 0b00111000) { // 0.001 l/h to 10 000 l/h
				desc = "volume flow";
				unit = "m³/h";
				exp = n - 6;
			}
			else if (id == 0b01000000) { // 0.0001 l/min to 1000 l/min
				desc = "volume flow";
				unit = "m³/min";
				exp = n - 7;
			}
			else if (id == 0b01001000) { // 0.001 ml/s to 10000 ml/s
				desc = "volume flow";
				unit = "m³/sec";
				exp = n - 9;
			}
			else if (id == 0b01010000) { // 0.001 kg/h to 10000 kg/h
				desc = "mass flow";
				unit = "kg/h";
				exp = n - 3;
			}
			else if (coding == 0b01101110) { // dimensionless
				desc = "units for HCA";
				unit = "";
			}
			else
				throw newException("reserved coding", binary(coding));
		}
		else {
			final int vifExtMask = 0b11111110;
			final int id = coding & vifExtMask;
			final int n = coding & ~vifExtMask;

			if (id == 0b10000000) { // 0.1 MWh to 1 MWh
				desc = "energy";
				unit = "Wh";
				exp = n + 5;
			}
			else if (id == 0b10001000) { // 0.1 GJ to 1 GJ
				desc = "energy";
				unit = "J";
				exp = n + 8;
			}
			else if (id == 0b10101000) { // 0.1 MW to 1 MW
				desc = "power";
				unit = "W";
				exp = n + 5;
			}
			else if (id == 0b10110000) { // 0.1 GJ/h to 1 GJ/h
				desc = "power";
				unit = "J/h";
				exp = n + 8;
			}
			else if (coding == dimensionlessCounter) {
				desc = "dimensionless counter";
				unit = "";
			}
			else
				throw newException("reserved coding", binary(coding));
		}

		description = desc;
		this.unit = unit;
		return exp;
	}

	// try to find the coding based on unit
	private int coding(final String unit) throws KNXFormatException
	{
		expUnitAdjustment = 0;
		// @formatter:off
		switch (unit) {
		case "Wh": return 0b00000000;
		case "MWh": expUnitAdjustment = 6; return 0b10000000;
		case "kJ": expUnitAdjustment = 3; return 0b00001000;
		case "GJ": expUnitAdjustment = 9; return 0b10001000;
		case "l": expUnitAdjustment = -3; return 0b00010000;
		case "kg": return 0b00011000;
		case "W": return 0b00101000;
		case "MW": expUnitAdjustment = 6; return 0b10101000;
		case "kJ/h": expUnitAdjustment = 3; return 0b00110000;
		case "GJ/h": expUnitAdjustment = 9; return 0b10110000;
		case "l/h": expUnitAdjustment = -3; return 0b00111000;
		case "l/min": expUnitAdjustment = -3; return 0b01000000;
		case "ml/s": expUnitAdjustment = -6; return 0b01001000;
		case "kg/h": return 0b01010000;
//		case "": return 0b01101110; // 'units for HCA', we will opt for 'dimensionless counter'
		case "": return dimensionlessCounter;
		default: throw newException("unsupported unit", unit);
		}
		// @formatter:on
	}

	private static short ubyte(final byte b)
	{
		return (short) (b & 0xff);
	}

	private static String binary(final int coding)
	{
		return String.format("0b%8s", Integer.toBinaryString(coding)).replace(' ', '0');
	}
}
