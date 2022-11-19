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

package tuwien.auto.calimero.dptxlator;

import java.lang.System.Logger.Level;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;

/**
 * Translator for KNX DPTs with main number 251, type <b>Color RGBW</b>. The KNX data type width is 6 bytes. The default
 * return value after creation is the RGBW value with all components not valid ({@code - - - - %}).
 * <p>
 * In value methods expecting string items, values are parsed as floating point value.
 */
public class DptXlatorRgbw extends DPTXlator {
	public static final String Description = "RGBW color";

	/**
	 * DPT ID 251.600, RGBW color; values from <b>0 0 0 0 %</b> to <b>100 100 100 100 %</b>.
	 */
	public static final DPT DptRgbw = new DPT("251.600", "RGBW color", "0 0 0 0", "100 100 100 100", "%");

	private static final Map<String, DPT> types;

	static {
		types = new HashMap<>();
		types.put(DptRgbw.getID(), DptRgbw);
	}

	private final NumberFormat formatter = NumberFormat.getNumberInstance();


	/**
	 * Creates a translator for {@link DptRgbw}.
	 *
	 * @throws KNXFormatException on not available DPT
	 */
	public DptXlatorRgbw() throws KNXFormatException {
		this(DptRgbw);
	}

	/**
	 * Creates a translator for the given datapoint type.
	 *
	 * @param dpt the requested datapoint type
	 * @throws KNXFormatException on not supported or not available DPT
	 */
	public DptXlatorRgbw(final DPT dpt) throws KNXFormatException {
		this(dpt.getID());
	}

	/**
	 * Creates a translator for the given datapoint type ID.
	 *
	 * @param dptId available implemented datapoint type ID
	 * @throws KNXFormatException on wrong formatted or not expected (available) {@code dptId}
	 */
	public DptXlatorRgbw(final String dptId) throws KNXFormatException {
		super(6);
		setTypeID(types, dptId);
		data = new short[6];
		formatter.setMaximumFractionDigits(1);
	}

	@Override
	public String getValue() {
		return fromDpt(0);
	}

	/**
	 * Sets one new translation item, replacing any old items.
	 *
	 * @param red {@code 0 ≤ red ≤ 100}
	 * @param green {@code 0 ≤ green ≤ 100}
	 * @param blue {@code 0 ≤ blue ≤ 100}
	 * @param white {@code 0 ≤ white ≤ 100}
	 */
	public final void setValue(final double red, final double green, final double blue, final double white) {
		data = toDpt(red, green, blue, white);
	}

	public final void setRed(final double value) {
		final short v = toDpt(value);
		data[0] = v; data[5] |= 0b1000;
	}

	public final void setGreen(final double value) {
		final short v = toDpt(value);
		data[1] = v; data[5] |= 0b0100;
	}

	public final void setBlue(final double value) {
		final short v = toDpt(value);
		data[2] = v; data[5] |= 0b0010;
	}

	public final void setWhite(final double value) {
		final short v = toDpt(value);
		data[3] = v; data[5] |= 0b0001;
	}

	public final Optional<Double> red() {
		return component(0);
	}

	public final Optional<Double> green() {
		return component(1);
	}

	public final Optional<Double> blue() {
		return component(2);
	}

	public final Optional<Double> white() {
		return component(3);
	}

	@Override
	public String[] getAllValues() {
		final int items = getItems();
		final String[] s = new String[items];
		for (int i = 0; i < items; ++i)
			s[i] = fromDpt(i);
		return s;
	}

	@Override
	public final Map<String, DPT> getSubTypes() {
		return types;
	}

	/**
	 * @return the subtypes of this translator
	 * @see DPTXlator#getSubTypesStatic()
	 */
	protected static Map<String, DPT> getSubTypesStatic() {
		return types;
	}

	private String fromDpt(final int index) {
		if (data[index * 6 + 4] != 0)
			logger.log(Level.WARNING, "DPT " + dpt.getID() + " " + dpt.getDescription() + ": reserved bits not 0");
		return appendUnit(component(index, 0) + " " + component(index, 1) + " " + component(index, 2) + " " + component(index, 3));
	}

	// component red = 0, ..., white = 3
	private String component(final int index, final int component) {
		final int mask = 1 << (3 - component);
		final boolean valid = (data[index * 6 + 5] & mask) == mask;
		if (valid)
			return formatter.format(data[index * 6 + component] * 100d / 255);
		return "-";
	}

	// component red = 0, ..., white = 3
	private Optional<Double> component(final int component) {
		final int index = 0;
		final int mask = 1 << (3 - component);
		final boolean valid = (data[index * 6 + 5] & mask) == mask;
		if (valid)
			return Optional.of(data[index * 6 + component] * 100d / 255);
		return Optional.empty();
	}

	@Override
	protected void toDPT(final String value, final short[] dst, final int index) throws KNXFormatException {
		final String[] components = removeUnit(value).split(" ");
		if (components.length != 4)
			throw newException("RGBW format requires 4 components", value);
		int valid = 0;
		for (int i = 0; i < 4; i++) {
			final int mask = 1 << (3 - i);
			if (!components[i].equals("-")) {
				valid |= mask;
				dst[index * 6 + i] = toDpt(components[i]);
			}
		}
		dst[index * 6 + 5] = (short) valid;
	}

	private short[] toDpt(final double red, final double green, final double blue, final double white) {
		final int valid = 0b1111;
		return new short[] { toDpt(red), toDpt(green), toDpt(blue), toDpt(white), 0, valid };
	}

	private short toDpt(final double value) {
		if (value < 0 || value > 100)
			throw new KNXIllegalArgumentException("RGBW component " + value + " out of range [0..100]");
		return (short) Math.round(value * 255 / 100);
	}

	private short toDpt(final String component) throws KNXFormatException {
		try {
			final double value = Double.parseDouble(component.replace(',', '.'));
			return toDpt(value);
		}
		catch (final NumberFormatException e) {
			throw newException("wrong value format", component);
		}
		catch (final KNXIllegalArgumentException e) {
			throw newException(e.getMessage(), component);
		}
	}
}
