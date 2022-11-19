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

import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static java.util.Collections.emptyList;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;

/**
 * Maintains available KNX datapoint main numbers and its associated DPT translators, and provides all available,
 * registered DP main numbers with the corresponding translator and an optional description of the type.<br>
 * For commonly used data types, the main types are declared as constants, although this doesn't necessarily indicate a
 * translator is actually available.<br>
 * All DPT translator implementations in this package are registered here and available by default. Translators might be
 * added or removed by the user.
 * <p>
 * A datapoint type consists of a data type and a dimension. The data type is referred to through a main number, the
 * existing dimensions of a data type are listed through sub numbers. The data type specifies format and encoding, while
 * dimension specifies the range and unit.<br>
 * A datapoint type identifier (DPT ID or dptId for short), stands for one particular datapoint type. The preferred -
 * but not enforced - way of naming a dptId is using the expression "<i>main number</i>.<i>sub number</i>".<br>
 * In short, a datapoint type has a dptId and standardizes one combination of format, encoding, range and unit.
 *
 * @author B. Malinowsky
 * @see DPTXlator
 */
public final class TranslatorTypes
{
	/**
	 * DPT main number for <b>B1 (boolean)</b>, number = {@value #TYPE_BOOLEAN}.
	 */
	public static final int TYPE_BOOLEAN = 1;

	/**
	 * DPT main number for <b>B2 (1 Bit controlled)</b>, number = {@value #TYPE_1BIT_CONTROLLED}.
	 */
	public static final int TYPE_1BIT_CONTROLLED = 2;

	/**
	 * DPT main number for <b>B1U3 (3 Bit controlled)</b>, number = {@value #TYPE_3BIT_CONTROLLED}.
	 */
	public static final int TYPE_3BIT_CONTROLLED = 3;

	/**
	 * DPT main number for <b>character set</b>, number = {@value #TYPE_CHARACTER_SET}.
	 */
	public static final int TYPE_CHARACTER_SET = 4;

	/**
	 * DPT main number for <b>8 Bit unsigned value</b>, number = {@value #TYPE_8BIT_UNSIGNED}.
	 */
	public static final int TYPE_8BIT_UNSIGNED = 5;

	/**
	 * DPT main number for <b>V8 (8 Bit signed value)</b>, shares main number with "Status with mode", number =
	 * {@value #TYPE_8BIT_SIGNED}.
	 */
	public static final int TYPE_8BIT_SIGNED = 6;

	/**
	 * DPT main number for <b>2-octet unsigned value</b>, number = {@value #TYPE_2OCTET_UNSIGNED}.
	 */
	public static final int TYPE_2OCTET_UNSIGNED = 7;

	/**
	 * DPT main number for <b>2-octet signed value</b>, number = {@value #TYPE_2OCTET_SIGNED}.
	 */
	public static final int TYPE_2OCTET_SIGNED = 8;

	/**
	 * DPT main number for <b>2-octet float value</b>, number = {@value #TYPE_2OCTET_FLOAT}.
	 */
	public static final int TYPE_2OCTET_FLOAT = 9;

	/**
	 * DPT main number for <b>time</b>, number = {@value #TYPE_TIME}.
	 */
	public static final int TYPE_TIME = 10;

	/**
	 * DPT main number for <b>date</b>, number = {@value #TYPE_DATE}.
	 */
	public static final int TYPE_DATE = 11;

	/**
	 * DPT main number for <b>4-octet unsigned value</b>, number = {@value #TYPE_4OCTET_UNSIGNED}.
	 */
	public static final int TYPE_4OCTET_UNSIGNED = 12;

	/**
	 * DPT main number for <b>4-octet signed value</b>, number = {@value #TYPE_4OCTET_SIGNED}.
	 */
	public static final int TYPE_4OCTET_SIGNED = 13;

	/**
	 * DPT main number for <b>4-octet float value</b>, number = {@value #TYPE_4OCTET_FLOAT}.
	 */
	public static final int TYPE_4OCTET_FLOAT = 14;

	/**
	 * DPT main number for <b>access data</b>, number = {@value #TYPE_ACCESS}.
	 */
	public static final int TYPE_ACCESS = 15;

	/**
	 * DPT main number for <b>string</b>, number = {@value #TYPE_STRING}.
	 */
	public static final int TYPE_STRING = 16;

	/**
	 * DPT main number for <b>scene number</b>, number = {@value #TYPE_SCENE_NUMBER}.
	 */
	public static final int TYPE_SCENE_NUMBER = 17;

	/**
	 * DPT main number for <b>scene control</b>, number = {@value #TYPE_SCENE_CONTROL}.
	 */
	public static final int TYPE_SCENE_CONTROL = 18;

	/**
	 * DPT main number for <b>date/time</b>, number = {@value #TYPE_DATE_TIME}.
	 */
	public static final int TYPE_DATE_TIME = 19;

	/**
	 * DPT main number for <b>8 Bit enumeration</b>, number = {@value #TYPE_8BIT_ENUM}.
	 */
	public static final int TYPE_8BIT_ENUM = 20;

	/**
	 * DPT main number for <b>UTF-8</b>, number = {@value #TYPE_UTF8}.
	 */
	public static final int TYPE_UTF8 = 28;

	/**
	 * DPT main number for <b>V64 (64 Bit signed value)</b>, number = {@value #TYPE_64BIT_SIGNED}.
	 */
	public static final int TYPE_64BIT_SIGNED = 29;

	/**
	 * DPT main number for <b>RGB color</b>, number = {@value #TYPE_RGB}.
	 */
	public static final int TYPE_RGB = 232;

	/**
	 * Maps a data type main number to a corresponding translator class doing the DPT translations. Objects of this type
	 * are immutable.
	 */
	public static class MainType
	{
		private final Class<? extends DPTXlator> xlator;
		private final String desc;
		private final int main;

		/**
		 * Creates a new main number to translator mapping.
		 *
		 * @param mainNumber main number assigned to the data type
		 * @param translator represents a translator class of type {@link DPTXlator}
		 * @param description textual information describing this data type to a user, use {@code null} for no
		 *        description
		 */
		public MainType(final int mainNumber, final Class<? extends DPTXlator> translator, final String description)
		{
			if (mainNumber <= 0)
				throw new KNXIllegalArgumentException("invalid main number");
			if (!DPTXlator.class.isAssignableFrom(translator) || DPTXlator.class.equals(translator))
				throw new KNXIllegalArgumentException(translator.getName() + " is not a valid DPT translator type");
			main = mainNumber;
			xlator = translator;
			desc = description == null ? "" : description;
		}

		/**
		 * Returns the data type main number.
		 *
		 * @return main number as int
		 */
		public final int getMainNumber()
		{
			return main;
		}

		/**
		 * Creates a new translator for the given datapoint type.
		 *
		 * @param dpt datapoint type specifying the particular translation behavior; if the datapoint type is not part
		 *        of the translator of this main type, a {@link KNXFormatException} is thrown
		 * @return the new {@link DPTXlator} instance
		 * @throws KNXFormatException to forward all target exceptions thrown in the constructor of the translator
		 * @throws KNXException thrown on translator class creation errors (e.g. security / access problems)
		 */
		public final DPTXlator createTranslator(final DPT dpt) throws KNXException
		{
			return createTranslator(dpt.getID());
		}

		/**
		 * Creates a new instance of the translator for the given datapoint type ID.
		 *
		 * @param dptId datapoint type ID for selecting a particular kind of value translation; if the datapoint type ID
		 *        is not part of the translator of this main type, a {@link KNXFormatException} is thrown
		 * @return the new {@link DPTXlator} instance
		 * @throws KNXFormatException to forward all target exceptions thrown in the constructor of the translator
		 * @throws KNXException thrown on translator class creation errors (e.g. security / access problems)
		 */
		public DPTXlator createTranslator(final String dptId) throws KNXException
		{
			try {
				return xlator.getConstructor(String.class).newInstance(dptId);
			}
			catch (final InvocationTargetException e) {
				// try to forward encapsulated target exception
				if (e.getTargetException() instanceof KNXFormatException)
					throw (KNXFormatException) e.getTargetException();
				// throw generic message
				throw new KNXFormatException("failed to init translator", dptId);
			}
			catch (final NoSuchMethodException e) {
				DPTXlator.logger.log(ERROR, "DPT translator is required to have a public constructor(String dptId)");
				throw new KNXException("interface specification error at translator");
			}
			catch (final Exception e) {
				// for SecurityException, InstantiationException, IllegalAccessException
				throw new KNXException("failed to create translator", e);
			}
		}

		/**
		 * Returns the translator class used for this main type.
		 * <p>
		 *
		 * @return the translator class as {@link Class} object
		 */
		public Class<? extends DPTXlator> getTranslator()
		{
			return xlator;
		}

		/**
		 * Returns the description to this main type, if any.
		 * <p>
		 *
		 * @return description as String, or the empty string if no description set
		 */
		public final String getDescription()
		{
			return desc;
		}

		/**
		 * Returns a map containing all implemented subtypes.
		 * <p>
		 *
		 * @return available subtypes as {@link Map}
		 * @throws KNXException thrown on problems accessing the translator while retrieving sub types (e.g. security /
		 *         access problem) for external, user supplied translators
		 * @see DPTXlator#getSubTypes()
		 */
		public Map<String, DPT> getSubTypes() throws KNXException
		{
			try {
				@SuppressWarnings("unchecked")
				final Map<String, DPT> m = (Map<String, DPT>) xlator
						.getDeclaredMethod("getSubTypesStatic", (Class<?>[]) null).invoke(null, (Object[]) null);
				return m;
			}
			catch (final NoSuchMethodException e) {
				throw new KNXException("no method to get subtypes, " + e.getMessage());
			}
			catch (final Exception e) {
				// for SecurityException and IllegalAccessException
				// no reason for InvocationTargetException
				throw new KNXException("security / access problem, " + e.getMessage());
			}
		}

		@Override
		public String toString()
		{
			return getDescription();
		}
	}

	private static final Map<Integer, MainType> map = Collections.synchronizedMap(new HashMap<>());

	private static final String[] builtinXlators = {
			"DptXlator16BitSet",
			"DPTXlator1BitControlled",
			"DPTXlator2ByteFloat",
			"DptXlator2ByteSigned",
			"DPTXlator2ByteUnsigned",
			"DPTXlator3BitControlled",
			"DPTXlator4ByteFloat",
			"DPTXlator4ByteSigned",
			"DPTXlator4ByteUnsigned",
			"DPTXlator64BitSigned",
			"DPTXlator8BitEnum",
			"DptXlator8BitSet",
			"DPTXlator8BitSigned",
			"DPTXlator8BitUnsigned",
			"DPTXlatorBoolean",
			"DptXlatorBrightnessClrTempControl",
			"DptXlatorBrightnessClrTempTrans",
			"DPTXlatorDate",
			"DPTXlatorDateTime",
			"DptXlatorMeteringValue",
			"DptXlatorRelativeControlRgb",
			"DptXlatorRelativeControlRgbw",
			"DptXlatorRelativeControlXyY",
			"DPTXlatorRGB",
			"DptXlatorRgbw",
			"DPTXlatorSceneControl",
			"DPTXlatorSceneNumber",
			"DPTXlatorString",
			"DPTXlatorTime",
			"DPTXlatorUtf8",
			"DptXlatorXyY",
			"DptXlatorXyYTransition",
	};

	static {
		try {
			for (final var x : builtinXlators)
				addTranslator("tuwien.auto.calimero.dptxlator." + x);
		}
		catch (final Exception e) {
			DPTXlator.logger.log(ERROR, "failed to initialize list of available DPT translators", e);
		}
	}

	private TranslatorTypes() {}


	private static void addTranslator(final String className)
	{
		try {
			final Class<?> c = Class.forName(className);
			if (DPTXlator.class.equals(c) || !DPTXlator.class.isAssignableFrom(c))
				return;

			@SuppressWarnings("unchecked")
			final Class<? extends DPTXlator> x = (Class<? extends DPTXlator>) c;
			@SuppressWarnings("unchecked")
			final Map<String, DPT> dpts = (Map<String, DPT>) x.getDeclaredMethod("getSubTypesStatic").invoke(null);
			final String id = dpts.values().iterator().next().getID();
			final String s = id.substring(0, id.indexOf('.'));
			final int mainNumber = Integer.parseInt(s);
			final String desc = descriptionFor(x) + " (main number " + mainNumber + ")";

			map.put(mainNumber, new MainType(mainNumber, x, desc));
			DPTXlator.logger.log(TRACE, "loaded DPT translator for {0}", desc);
		}
		catch (ClassNotFoundException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
				| NoSuchMethodException | SecurityException e) {
			DPTXlator.logger.log(WARNING, "lookup DPT translator class {0}", className, e);
		}
	}

	private static String descriptionFor(final Class<? extends DPTXlator> x) throws IllegalAccessException
	{
		try {
			final Field f = x.getField("Description");
			if (f.getType() == String.class)
				return (String) f.get(null);
		}
		catch (final NoSuchFieldException e) {}
		String name = x.getSimpleName();
		// strip off the DPTXlator prefix if we have that
		if (name.toLowerCase().indexOf("dptxlator") == 0)
			name = name.substring("dptxlator".length());
		// create human readable name by inserting some spaces
		return name.replaceAll("([A-Z])", " $1").trim();
	}

	/**
	 * Returns the {@link MainType} object assigned the given data type main number.
	 *
	 * @param mainNumber main type to lookup
	 * @return the main type information found, or {@code null} if main number not listed
	 */
	public static MainType getMainType(final int mainNumber)
	{
		return map.get(mainNumber);
	}

	/**
	 * Returns all available data types which have a DPT translator implementation assigned.
	 * <p>
	 * The map returned is the same used by this class for type lookup. Map entries can be added, likewise entries might
	 * be removed to change future lookup results.
	 *
	 * @return a {@link Map} containing all data types as {@link MainType} objects
	 */
	public static Map<Integer, MainType> getAllMainTypes()
	{
		return map;
	}

	/**
	 * Returns all main types of a specific data type size, based on the currently available main types as provided by
	 * {@link TranslatorTypes#getAllMainTypes()}.
	 * <p>
	 * For example, when specifying a type size of {@code 2}, the returned list will contain the main types with
	 * number 9 (<b>2-byte float</b>) and number 7 (<b>2 byte unsigned value</b>), assuming both are also returned by
	 * {@link TranslatorTypes#getAllMainTypes()}.
	 *
	 * @param typeSize the data type size in bytes, use {@code 0} for main types having a 6 bit ASDU
	 * @return list of all available main types of the requested type size or the empty list
	 */
	public static List<MainType> getMainTypesBySize(final int typeSize)
	{
		final List<MainType> l = new ArrayList<>();
		for (final Iterator<MainType> i = map.values().iterator(); i.hasNext();) {
			final MainType type = i.next();
			try {
				final String dptId = type.getSubTypes().keySet().iterator().next();
				final int size = type.createTranslator(dptId).getTypeSize();
				if (size == typeSize)
					l.add(type);
			}
			catch (final KNXException e) {}
		}
		return l;
	}

	/**
	 * Returns all main types of a specific data type size, based on the currently available main types as provided by
	 * {@link TranslatorTypes#getAllMainTypes()}.
	 * <p>
	 * For example, when specifying a size of {@code 2} bits, the returned list will contain the main type with
	 * main number 2 (translator <b>1 Bit controlled</b>), assuming it is returned by
	 * {@link TranslatorTypes#getAllMainTypes()}.
	 *
	 * @param size the data type size in bits
	 * @return list of all available main types of the requested type size or the empty list
	 */
	public static List<MainType> ofBitSize(final int size)
	{
		if (size < 5) {
			final MainType mainType = map.get(
					size == 1 ? TYPE_BOOLEAN : size == 2 ? TYPE_1BIT_CONTROLLED : size == 4 ? TYPE_3BIT_CONTROLLED : 0);
			return Optional.ofNullable(mainType).map(Collections::singletonList).orElse(emptyList());
		}
		final List<MainType> l = new ArrayList<>();
		for (final MainType type : map.values()) {
			try {
				final String dptId = type.getSubTypes().keySet().iterator().next();
				final int bits = type.createTranslator(dptId).getTypeSize() * 8;
				if (bits == size)
					l.add(type);
			}
			catch (final KNXException e) {}
		}
		return l;
	}

	/**
	 * Does a lookup if the specified DPT is supported by a DPT translator.
	 *
	 * @param mainNumber data type main number, number &ge; 0; use 0 to infer translator type from {@code dptId}
	 *        argument only
	 * @param dptId datapoint type ID to lookup this particular kind of value translation
	 * @return {@code true} iff translator was found, {@code false} otherwise
	 */
	public static boolean hasTranslator(final int mainNumber, final String dptId)
	{
		try {
			final MainType t = getMainType(getMainNumber(mainNumber, dptId));
			if (t != null)
				return t.getSubTypes().get(dptId) != null;
		}
		catch (final NumberFormatException e) {}
		catch (final KNXException e) {}
		return false;
	}

	/**
	 * Creates a DPT translator for the given datapoint type ID.
	 * <p>
	 * The translation behavior of a DPT translator instance is uniquely defined by the supplied datapoint type ID.
	 * <p>
	 * If the {@code dptId} argument is built up the recommended way, that is "<i>main number</i>.<i>sub number</i>
	 * ", the {@code mainNumber} argument might be left 0 to use the datapoint type ID only.<br>
	 * Note, that we don't enforce any particular or standardized format on the {@code dptId} structure, so using a
	 * different formatted dptId solely without main number argument results in undefined behavior.
	 *
	 * @param mainNumber data type main number, number &ge; 0; use 0 to infer translator type from {@code dptId}
	 *        argument only
	 * @param dptId datapoint type ID for selecting a particular kind of value translation
	 * @return the new {@link DPTXlator} object
	 * @throws KNXException on main type not found or creation failed (refer to
	 *         {@link MainType#createTranslator(String)})
	 */
	public static DPTXlator createTranslator(final int mainNumber, final String dptId) throws KNXException
	{
		int main = 0;
		try {
			main = getMainNumber(mainNumber, dptId);
		}
		catch (final NumberFormatException | IndexOutOfBoundsException e) {}
		final MainType type = map.get(main);
		if (type == null)
			throw new KNXException("no DPT translator available for main number " + main + " (ID " + dptId + ")");

		final String id = dptId != null && !dptId.isEmpty() ? dptId : type.getSubTypes().keySet().iterator().next();
		return type.createTranslator(id);
	}

	/**
	 * Creates a DPT translator for the given datapoint type main/sub number.
	 *
	 * @param mainNumber datapoint type main number, 0 &lt; mainNumber
	 * @param subNumber datapoint type sub number selecting a particular kind of value translation; use 0 to request any
	 *        type ID of that translator (in that case, appending the physical unit for string values is disabled)
	 * @param data (optional) KNX datapoint data to set in the created translator for translation
	 * @return the new {@link DPTXlator} object
	 * @throws KNXException if no matching DPT translator is available or creation failed (see
	 *         {@link MainType#createTranslator(String)})
	 */
	public static DPTXlator createTranslator(final int mainNumber, final int subNumber, final byte... data)
		throws KNXException
	{
		final MainType type = map.get(mainNumber);
		if (type == null)
			throw new KNXException("no DPT translator available for main number " + mainNumber);

		final boolean withSub = subNumber != 0;
		final String id = withSub ? String.format("%d.%03d", mainNumber, subNumber)
				: type.getSubTypes().keySet().iterator().next();
		final DPTXlator t = type.createTranslator(id);
		t.setAppendUnit(withSub);
		if (data.length > 0)
			t.setData(data);
		return t;
	}

	/**
	 * Creates a DPT translator for the given datapoint type.
	 * <p>
	 * The translation behavior of a DPT translator instance is uniquely defined by the supplied datapoint type.
	 * <p>
	 * If translator creation according {@link #createTranslator(int, String)} fails, all available main types are
	 * enumerated to find an appropriate translator.
	 *
	 * @param dpt datapoint type selecting a particular kind of value translation
	 * @param data (optional) KNX datapoint data to set in the created translator for translation
	 * @return the new {@link DPTXlator} object
	 * @throws KNXException if no matching DPT translator is available or creation failed
	 */
	public static DPTXlator createTranslator(final DPT dpt, final byte... data) throws KNXException {
		final DPTXlator t = createTranslator(dpt);
		if (data.length > 0)
			t.setData(data);
		return t;
	}

	private static DPTXlator createTranslator(final DPT dpt) throws KNXException {
		try {
			return createTranslator(0, dpt.getID());
		}
		catch (final KNXException e) {
			for (final MainType type : map.values())
				try {
					return type.createTranslator(dpt);
				}
				catch (final KNXException ignore) {}
		}
		throw new KNXException("failed to create translator for DPT " + dpt.getID());
	}

	/**
	 * Creates a DPT translator for the given datapoint type ID.
	 *
	 * @param dptId datapoint type ID, formatted as {@code <main number>.<sub number>} with sub
	 *        numbers &lt; 100 zero-padded to 3 digits, e.g. "1.001"
	 * @param data (optional) KNX datapoint data to set in the created translator for translation
	 * @return the new {@link DPTXlator} object
	 * @throws KNXException if no matching DPT translator is available or creation failed (see
	 *         {@link MainType#createTranslator(String)})
	 */
	public static DPTXlator createTranslator(final String dptId, final byte... data)
		throws KNXException, KNXIllegalArgumentException
	{
		final DPTXlator t = createTranslator(0, dptId);
		if (data.length > 0)
			t.setData(data);
		return t;
	}

	// throws NumberFormatException
	private static int getMainNumber(final int mainNumber, final String dptId)
	{
		return mainNumber != 0 ? mainNumber : Integer.parseInt(dptId.substring(0, dptId.indexOf('.')));
	}
}
