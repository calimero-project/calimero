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

package tuwien.auto.calimero.dptxlator;

import java.lang.System.Logger;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.AbstractCollection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.log.LogService;

/**
 * DPT translator interface for data conversion between KNX DPTs and java types.
 * <p>
 * A translator supports translation of more than one values / DPTs at the same time.<br>
 * After creation, a translator initially contains at least one valid default item (i.e.
 * value and data) representation for return through a {@code getValue}- or
 * {@code getData}-like method call.
 * <p>
 * The naming convention used for translator methods is to use methods comprising "data"
 * in its name for handling KNX data types (usually contained in byte arrays), while
 * methods comprising "value" for handling java types.
 * <p>
 * A translator shall publish its supported subtypes as constants of type {@link DPT}
 * through its interface.
 * <p>
 * Although there is no restriction on changing the datapoint type ID of a translator
 * after creation (and consequently adjust all contained translation items to the new
 * subtype), there seems no real requirement for this; therefore it is not implemented nor
 * supported.
 * <p>
 * DPT translator implementations are not required to be thread safe. All translators
 * provided in this package are not thread safe.
 *
 * @author B. Malinowsky
 */
public abstract class DPTXlator
{
	/**
	 * Name of the log service used in DPT translators.
	 */
	public static final String LOG_SERVICE = "calimero.dptxlator.DptXlator";

	/**
	 * Logger object for all translators.
	 */
	protected static final Logger logger = LogService.getLogger(LOG_SERVICE);

	/**
	 * Array containing KNX data type values.
	 * <p>
	 * For every element entry, only the lower byte is allowed to be set. This way, it is
	 * possible to store and access unsigned bytes.<br>
	 * The length of the array indicates how much KNX data values are contained for conversion.
	 */
	protected short[] data;

	/**
	 * The datapoint type set for the translator.
	 */
	protected DPT dpt;

	/**
	 * Specifies the size of the data type in bytes, set {@code 0} if type size
	 * &lt;= 6 bits.
	 * <p>
	 * It is used for calculating the number of items in the translator, and also by users
	 * for detecting an optimized (short) group structure format.
	 */
	protected final int typeSize;

	private final int bitSize;

	/**
	 * Behavior regarding appending a DPT engineering unit.
	 * <p>
	 * Methods capable of returning an item value together the engineering unit of the
	 * DPT, should append the unit on {@code true}, and omit any unit
	 * representation on {@code false}; default setting is {@code true}.
	 * Only relevant for DPTs with an associated engineering unit.
	 */
	protected boolean appendUnit = true;

	DPTXlator(final boolean reserved, final int bitSize) {
		this.bitSize = bitSize;
		typeSize = bitSize / 8;
		data = new short[typeSize == 0 ? 1 : typeSize];
	}

	/**
	 * Creates the new translator and initializes the data type size.
	 *
	 * @param dataTypeSize size in bytes of the KNX data type, use 0 if the type size &lt;= 6 bits
	 */
	public DPTXlator(final int dataTypeSize)
	{
		this(false, dataTypeSize * 8);
	}

	/**
	 * Translates the array of strings according to the set datapoint ID.
	 * <p>
	 * If, and only if, all items in {@code values} can successfully be translated,
	 * they get stored by the translator, replacing any old items. On
	 * {@code values.length == 0}, no action is performed.<br>
	 * Textual commands contained in {@code values} are treated case insensitive.
	 *
	 * @param values string array holding values for translation
	 * @throws KNXFormatException if an item in {@code values} can't be translated
	 *         due to a wrong formatted content, or if {@code value}doesn't fit
	 *         into KNX data type
	 */
	public void setValues(final String... values) throws KNXFormatException
	{
		if (values.length > 0) {
			final short[] buf = new short[(typeSize > 0 ? typeSize : 1) * values.length];
			for (int i = 0; i < values.length; ++i)
				toDPT(values[i], buf, i);
			data = buf;
		}
	}

	/**
	 * Returns all translation items as strings currently contained in this translator.
	 * <p>
	 * The items are ordered the same way handed to the translator in the first place
	 * (FIFO, increasing byte index).
	 *
	 * @return an array of strings with values represented as strings
	 * @see #getValue()
	 */
	public abstract String[] getAllValues();

	/**
	 * Translates the {@code value} according to the set datapoint ID.
	 * <p>
	 * If, and only if, {@code value} can successfully be translated, it gets
	 * stored by the translator, replacing any old items. Textual commands contained in
	 * {@code value} are treated case insensitive.<br>
	 * The {@code value} string might have its unit of measure appended (units are
	 * case sensitive).
	 *
	 * @param value value represented as string for translation, case insensitive
	 * @throws KNXFormatException if {@code value} can't be translated due to wrong
	 *         formatted content, or if {@code value}doesn't fit into KNX data type
	 */
	public void setValue(final String value) throws KNXFormatException
	{
		final short[] buf = new short[typeSize > 0 ? typeSize : 1];
		toDPT(value, buf, 0);
		data = buf;
	}

	public void setValue(final double value) throws KNXFormatException {
		throw new KNXFormatException("No simple numeric representation possible");
	}

	/**
	 * Returns the first value stored by this translator formatted into a string,
	 * according to the subtype ID.
	 * <p>
	 * If the subtype has a unit of measurement, it is appended after the value according
	 * to {@link DPTXlator#setAppendUnit(boolean)}.<br>
	 *
	 * @return a string representation of the value
	 * @see #getType()
	 */
	public String getValue()
	{
		return getAllValues()[0];
	}

	/**
	 * Returns the numeric representation of the first item stored by this translator, if the DPT
	 * value can be represented numerically.
	 *
	 * @return the numeric representation of the value
	 * @throws KNXFormatException if the value cannot be represented numerically
	 */
	public double getNumericValue() throws KNXFormatException
	{
		throw new KNXFormatException("No simple numeric representation possible");
	}

	/**
	 * See {@link #setData(byte[], int)}, with offset 0.
	 *
	 * @param data byte array containing KNX DPT item(s)
	 */
	public final void setData(final byte[] data)
	{
		setData(data, 0);
	}

	/**
	 * Sets the data array with KNX datapoint type items for translation.
	 * <p>
	 * The {@code data} array contains at least one DPT item, the new item(s) will
	 * replace any other items set in the translator before.<br>
	 * The number of items (KNX data values) for translation in {@code data} is
	 * inferred from the length of the usable {@code data} range:<br>
	 * {@code items = (data.length - offset) / (length of KNX data type)}
	 * <p>
	 * In general, the KNX data type width is implicitly known in the context where a
	 * translator is invoked (e.g., by appropriate DP configuration). Therefore,
	 * {@code data.length} will satisfy the minimum acceptable length. If this is
	 * not the case, {@link KNXIllegalArgumentException} has to be caught and handled in
	 * the caller's context.
	 *
	 * @param data byte array containing KNX DPT item(s)
	 * @param offset offset into {@code data} from where to start, {@code 0 ≤ offset < data.length}
	 * @throws KNXIllegalArgumentException if {@code data.length} - offset &lt;
	 *         data type width of this DPTXlator
	 */
	public void setData(final byte[] data, final int offset)
	{
		if (offset < 0 || offset > data.length)
			throw new KNXIllegalArgumentException("illegal offset " + offset);
		final int size = Math.max(1, getTypeSize());
		final int length = (data.length - offset) / size * size;
		if (length == 0)
			throw new KNXIllegalArgumentException("DPT " + dpt.getID() + " " + dpt.getDescription() + ": data length "
					+ (data.length - offset) + " < required datapoint type width " + size);
		this.data = new short[length];
		for (int i = 0; i < length; ++i)
			this.data[i] = ubyte(data[offset + i]);
	}

	/**
	 * Returns a copy of all items stored by this translator translated into DPTs.
	 *
	 * @return byte array with KNX DPT value items
	 */
	public byte[] getData()
	{
		return getData(new byte[data.length], 0);
	}

	/**
	 * Copies KNX DPT value items stored by this translator into {@code dst}, starting at
	 * {@code offset}.
	 * <p>
	 * The number of items copied depends on the usable {@code dst} range, i.e., how many items
	 * completely fit into {@code dst.length - offset}. If the usable range is too short, no
	 * item is copied at all, and {@code dst} is not modified.<br>
	 * Datapoint types shorter than 1 bytes only change the affected lower bit positions, leaving
	 * the upper (high) bits of {@code dst} bytes untouched.
	 *
	 * @param dst byte array for storing DPT values
	 * @param offset offset into {@code dst} from where to start, {@code 0 ≤ offset < dst.length}
	 * @return {@code dst}
	 * @throws KNXIllegalArgumentException if the usable destination range of {@code dst} is
	 *         not sufficient to hold at least 1 item
	 */
	public byte[] getData(final byte[] dst, final int offset)
	{
		final int min = Math.min(data.length, dst.length - offset);
		// align to multiples of typeSize
		final int end = typeSize > 0 ? min / typeSize * typeSize : min;
		if (min > 0 && end == 0) {
			throw new KNXIllegalArgumentException("insufficient space in destination range "
					+ "for DPT " + dpt.getID() + " (data length " + min + " < "
					+ Math.max(1, getTypeSize()) + ")");
		}
		for (int i = 0; i < end; ++i)
			dst[offset + i] = (byte) data[i];
		return dst;
	}

	/**
	 * Sets the behavior regarding appending a DPT engineering unit to items returned by
	 * this translator.
	 * <p>
	 * Translator methods capable of appending an available DPT unit will act according
	 * this setting.
	 *
	 * @param append {@code true} to append a DPT unit if any available,
	 *        {@code false} to omit any unit
	 */
	public final void setAppendUnit(final boolean append)
	{
		appendUnit = append;
	}

	/**
	 * Returns the number of translation items currently in the translator.
	 *
	 * @return items number
	 */
	public int getItems()
	{
		// this calculation should fit for all correctly implemented translators...
		return typeSize == 0 ? data.length : data.length / typeSize;
	}

	/**
	 * Returns the datapoint type used by the translator for translation.
	 * <p>
	 * The DPT distinguishes between the different subtypes available for a KNX data type.
	 * It specifies the dimension, consisting of range and unit attributes.
	 *
	 * @return datapoint type in a {@link DPT}
	 */
	public final DPT getType()
	{
		return dpt;
	}

	/**
	 * Returns all available, implemented subtypes for the translator.
	 * <p>
	 * A subtype, identified through a sub number, specifies the available dimension,
	 * consisting of range and unit attributes. Together with the main type information
	 * this uniquely defines a datapoint type.<br>
	 * The datapoint type information is contained in a {@link DPT} object.
	 * <p>
	 * New or modified DPT information can be made available to the translator by adding
	 * entries to the map, likewise map entries might be removed. In other words, the map
	 * returned is the same used by the translators of one main type for DPT lookup.
	 * Changes to the map influence all translators of the same main type.<br>
	 * Changes of the DPT currently used by the translator take effect on the next new
	 * translator created using that DPT.<br>
	 * The map itself is not synchronized.
	 *
	 * @return subtypes as {@link Map}, key is the subtype ID of type string, value of
	 *         type {@link DPT}
	 */
	public abstract Map<String, DPT> getSubTypes();

	/**
	 * Returns the KNX data type size in bits for one value item.
	 *
	 * @return type size in bits
	 */
	public int bitSize() {
		return bitSize;
	}

	/**
	 * Returns the KNX data type size in bytes for one value item.
	 * <p>
	 * If the data type size is &lt;= 6 bits, 0 is returned.
	 *
	 * @return type size in bytes, 0 for types &lt;= 6 bits
	 */
	public int getTypeSize()
	{
		return typeSize;
	}

	public List<DPTXlator> split()
	{
		if (getItems() > 1) {
			final List<DPTXlator> l = new ArrayList<>();
			final int size = Math.max(getTypeSize(), 1);
			final byte[] range = new byte[size];
			try {
				final Constructor<? extends DPTXlator> c = getClass().getConstructor(DPT.class);
				for (int offset = 0; offset < data.length; offset += size) {
					for (int i = 0; i < size; i++)
						range[i] = (byte) data[offset + i];

					final DPTXlator t = c.newInstance(getType());
					t.setData(range);
					l.add(t);
				}
				return l;
			}
			catch (ReflectiveOperationException | IllegalArgumentException /*| SecurityException*/ e) {}
		}
		return Collections.singletonList(this);
	}

	/**
	 * Returns a string of the used DPT together with all translation items currently
	 * contained in this translator.
	 * <p>
	 * The string consists of a list of values in the order they are returned by
	 * {@link #getAllValues()}. Adjacent items are separated as specified by
	 * {@link AbstractCollection#toString()}.
	 *
	 * @return a string representation of the translation values
	 */
	@Override
	public String toString()
	{
		return "DPT " + dpt.getID() + " " + Arrays.asList(getAllValues()).toString();
	}

	/**
	 * Translates a string value representation into KNX data type according the current
	 * DPT and stores the result into {@code dst}. The index parameter specifies
	 * the item index of the value. The translated KNX data is stored at the corresponding
	 * array offset in {@code dst}. Calculation of offset:
	 * {@code offset = index * KNX data type size}.
	 *
	 * @param value value to translate
	 * @param dst destination array for resulting KNX data
	 * @param index item index in destination array
	 * @throws KNXFormatException if {@code value} can't be translated due to wrong
	 *         formatted content, or if {@code value}doesn't fit into KNX data
	 *         type
	 */
	protected abstract void toDPT(String value, short[] dst, int index) throws KNXFormatException;

	/**
	 * Sets the DPT for the translator to use for translation, doing a lookup before in
	 * the translator's map containing the available, implemented datapoint types.
	 *
	 * @param availableTypes map of the translator with available, implemented DPTs; the
	 *        map key is a dptID string, map value is of type {@link DPT}
	 * @param dptID the ID as string of the datapoint type to set
	 * @throws KNXFormatException on DPT not available
	 */
	protected void setTypeID(final Map<String, DPT> availableTypes, final String dptID)
		throws KNXFormatException
	{
		final DPT t = availableTypes.get(dptID);
		if (t == null) {
			// don't call newException because dpt is not set
			throw new KNXFormatException("DPT " + dptID + " is not available", dptID);
		}
		dpt = t;
	}

	/**
	 * Returns all available subtypes for the translator class, equal to
	 * {@link #getSubTypes()}, every DPT translator has to implement this method. It is
	 * used for subtype listings without creating a translator object.
	 * <p>
	 * Note, since this is a class method, static binding is used.<br>
	 * In particular, the method is invoked without reference to a particular object, and
	 * hidden by declarations with the same signature in a sub type. A correct invocation
	 * is done using the declared type that actually contains the method declaration
	 * returning the available sub types.
	 *
	 * @return subtypes as {@link Map}, key is the subtype ID of type string, value of
	 *         type {@link DPT}
	 */
	protected static Map<String, DPT> getSubTypesStatic()
	{
		throw new IllegalStateException("invoke on specific translator");
	}

	final String appendUnit(final String value)
	{
		if (appendUnit)
			return value + " " + dpt.getUnit();
		return value;
	}

	/**
	 * Returns value with unit cut off at end of string, if current DPT has a unit specified.
	 * Whitespace are removed from both ends.
	 *
	 * @param value value string representation
	 * @return trimmed value string without unit
	 */
	final String removeUnit(final String value)
	{
		final int i;
		if (dpt.getUnit().length() > 0 && (i = value.lastIndexOf(dpt.getUnit())) > -1)
			return value.substring(0, i).trim();
		// java number parsing routines are really picky, remove WS
		return value.trim();
	}

	static final short ubyte(final int value)
	{
		return (short) (value & 0xff);
	}

	static Map<String, DPT> loadDatapointTypes(final Class<? extends DPTXlator> translator) {
		final Map<String, DPT> types = new HashMap<>();
		final Field[] fields = translator.getFields();
		for (int i = 0; i < fields.length; i++) {
			try {
				final Object o = fields[i].get(null);
				if (o instanceof DPT) {
					final DPT dpt = (DPT) o;
					types.put(dpt.getID(), dpt);
				}
			}
			catch (final IllegalAccessException e) {}
		}
		return types;
	}

	final KNXFormatException newException(final String msg, final String item, final Exception cause)
	{
		final String s = dpt.getID() + " " + dpt.getDescription() + ": " + msg;
		return new KNXFormatException(s, item, cause);
	}

	final KNXFormatException newException(final String msg, final String item)
	{
		return newException(msg, item, null);
	}
}
