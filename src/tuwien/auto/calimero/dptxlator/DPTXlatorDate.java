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

import java.lang.System.Logger.Level;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.util.HashMap;
import java.util.Map;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;

/**
 * Translator for KNX DPTs with main number 11, type <b>date</b>.
 * <p>
 * The KNX data type width is 3 bytes, containing year, month, and day of month information. Date calculation is based
 * on the system default time zone and locale. All time information behaves in strict (i.e., non-lenient) mode; no value
 * overflow is allowed and values are not normalized or adjusted using the next, larger field.
 * <p>
 * The default return value after creation is {@code 2000-01-01}.
 *
 * @author B. Malinowsky
 */
public class DPTXlatorDate extends DPTXlator
{
	/**
	 * DPT ID 11.001, Date; values from <b>1990-01-01</b> to <b>2089-12-31</b>.
	 */
	public static final DPT DPT_DATE = new DPT("11.001", "Date", "1990-01-01", "2089-12-31", "yyyy-mm-dd");

	// strict resolver style is default for ISO_DATE
	static final ResolverStyle defaultResolverStyle = ResolverStyle.STRICT;

	private static final int DAY = 0;
	private static final int MONTH = 1;
	private static final int YEAR = 2;

	// ??? maybe just convert everything based on ZoneOffset.UTC
	private static volatile DateTimeFormatter dtf = DateTimeFormatter.ISO_DATE.withResolverStyle(defaultResolverStyle);
	private static final Map<String, DPT> types;

	static {
		types = new HashMap<>(3);
		types.put(DPT_DATE.getID(), DPT_DATE);
	}

	/**
	 * Creates a translator for DPT ID 11.001, date.
	 */
	public DPTXlatorDate() {
		super(3);
		dpt = DPT_DATE;
		data = new short[] { 1, 1, 0 };
	}

	/**
	 * Creates a translator for the given datapoint type.
	 *
	 * @param dpt the requested datapoint type
	 * @throws KNXFormatException on not supported or not available DPT
	 */
	public DPTXlatorDate(final DPT dpt) throws KNXFormatException
	{
		this(dpt.getID());
	}

	/**
	 * Creates a translator for the given datapoint type ID.
	 *
	 * @param dptId available implemented datapoint type ID
	 * @throws KNXFormatException on wrong formatted or not expected (available) {@code dptID}
	 */
	public DPTXlatorDate(final String dptId) throws KNXFormatException
	{
		super(3);
		setTypeID(types, dptId);
		data = new short[] { 1, 1, 0 };
	}

	/**
	 * Sets a user defined date value format used by all instances of this class.
	 * <p>
	 * The pattern is specified according to {@link DateTimeFormatter}. All date information, supplied and returned in
	 * textual representation, will be parsed/formatted according to this pattern. The format will use the default
	 * format locale. If requesting a textual date representation, and using this value format leads to errors due to an
	 * invalid calendar date, a short error message string will be returned.
	 *
	 * @param pattern the new pattern specifying the value date format
	 * @see #useValueFormat(DateTimeFormatter)
	 */
	public static final void useValueFormat(final String pattern)
	{
		useValueFormat(DateTimeFormatter.ofPattern(pattern).withResolverStyle(defaultResolverStyle));
	}

	/**
	 * Sets a user defined date value format used by all instances of this class.
	 *
	 * @param formatter new date/time formatter
	 */
	public static final void useValueFormat(final DateTimeFormatter formatter)
	{
		dtf = formatter;
	}

	@Override
	public String[] getAllValues()
	{
		final String[] buf = new String[data.length / 3];
		for (int i = 0; i < buf.length; ++i)
			buf[i] = fromDPT(i);
		return buf;
	}

	@Override
	public void setValue(final double milliseconds) {
		setValue((long) milliseconds);
	}

	/**
	 * Sets the year, month, and day of month for the first date item.
	 * <p>
	 * Any other items in the translator are discarded on successful set.
	 *
	 * @param year year value, 1990 &lt;= year &lt;= 2089
	 * @param month month value, 1 &lt;= month &lt;= 12
	 * @param day day value, 1 &lt;= day &lt;= 31
	 */
	public final void setValue(final int year, final int month, final int day)
	{
		data = set(year, month, day, new short[3], 0);
	}

	/**
	 * Returns the day information.
	 *
	 * @return day of month value, 1 &lt;= day &lt;= 31
	 */
	public final int getDay()
	{
		return data[DAY];
	}

	/**
	 * Returns the month information.
	 *
	 * @return month value, 1 &lt;= month &lt;= 12
	 */
	public final int getMonth()
	{
		return data[MONTH];
	}

	/**
	 * @return month-of-year
	 */
	public final Month month() { return Month.of(getMonth()); }

	/**
	 * Returns the year information.
	 *
	 * @return year value, 1990 &lt;= year &lt;= 2089
	 */
	public final int getYear()
	{
		return absYear(data[YEAR]);
	}

	/**
	 * @return the local date obtained from year, month, and day of the first translation item
	 * @throws DateTimeException if the value of any field is out of range, or if the day-of-month is invalid for the
	 *         month-year
	 */
	public final LocalDate localDate()
	{
		return localDate(0);
	}

	/**
	 * Sets the date for the first item using UTC millisecond information.
	 *
	 * @param milliseconds time value in milliseconds from the epoch
	 */
	public final void setValue(final long milliseconds)
	{
		data = toDPT(milliseconds, new short[3], 0);
	}

	/**
	 * Returns the date information in UTC milliseconds, using year, month and day information.
	 *
	 * @return the date as time in milliseconds from the epoch
	 * @throws KNXFormatException on invalid calendar date
	 */
	public final long getValueMilliseconds() throws KNXFormatException
	{
		return fromDPTMillis(0);
	}

	@Override
	public double getNumericValue() throws KNXFormatException
	{
		return getValueMilliseconds();
	}

	@Override
	public void setData(final byte[] data, final int offset)
	{
		if (offset < 0 || offset > data.length)
			throw new KNXIllegalArgumentException("illegal offset " + offset);
		final int size = (data.length - offset) / 3 * 3;
		if (size == 0)
			throw new KNXIllegalArgumentException("DPT " + dpt.getID() + " " + dpt.getDescription() + ": data length "
					+ size + " < required datapoint type width " + Math.max(1, getTypeSize()));
		final short[] buf = new short[size];
		int item = 0;
		for (int i = offset; i < size + offset; i += 3) {
			set(absYear(data[i + YEAR] & 0x7F), data[i + MONTH] & 0x0F, data[i + DAY] & 0x1F, buf, item++);
			// check reserved bits
			if ((data[i + YEAR] & ~0x7F) + (data[i + MONTH] & ~0x0F) + (data[i + DAY] & ~0x1F) != 0)
				logger.log(Level.WARNING, "DPT " + dpt.getID() + " " + dpt.getDescription() + ": reserved bit not 0");
		}
		this.data = buf;
	}

	@Override
	public Map<String, DPT> getSubTypes()
	{
		return types;
	}

	/**
	 * @return the subtypes of the date translator type
	 * @see DPTXlator#getSubTypesStatic()
	 */
	protected static Map<String, DPT> getSubTypesStatic()
	{
		return types;
	}

	private String fromDPT(final int index)
	{
		return dtf.format(localDate(index));
	}

	private long fromDPTMillis(final int index) throws KNXFormatException
	{
		try {
			return localDate(index).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli();
		}
		catch (final Exception e) {
			throw newException("invalid date", "index " + index, e);
		}
	}

	private LocalDate localDate(final int index)
	{
		final int i = index * 3;
		final int d = data[i + DAY];
		final int m = data[i + MONTH];
		final int y = absYear(data[i + YEAR]);
		return LocalDate.of(y, m, d);
	}

	@Override
	protected void toDPT(final String value, final short[] dst, final int index) throws KNXFormatException
	{
		final String trimmed = value.trim();
		try {
			final TemporalAccessor date = dtf.parse(trimmed);
			final int y = date.get(ChronoField.YEAR_OF_ERA);
			final int m = date.get(ChronoField.MONTH_OF_YEAR);
			final int d = date.get(ChronoField.DAY_OF_MONTH);
			set(y, m, d, dst, index);
		}
		catch (final Exception e) {
			throw newException("invalid date", trimmed, e);
		}
	}

	private static short[] toDPT(final long milliseconds, final short[] dst, final int index)
	{
		final LocalDate date = Instant.ofEpochMilli(milliseconds).atZone(ZoneId.systemDefault()).toLocalDate();
		set(date.getYear(), date.getMonthValue(), date.getDayOfMonth(), dst, index);
		return dst;
	}

	private static short[] set(final int year, final int month, final int day, final short[] dst, final int index)
	{
		if (year < 1990 || year > 2089)
			throw new KNXIllegalArgumentException("year out of range [1990..2089]");
		if (month < 1 || month > 12)
			throw new KNXIllegalArgumentException("month out of range [1..12]");
		if (day < 1 || day > 31)
			throw new KNXIllegalArgumentException("day out of range [1..31]");
		final int i = 3 * index;
		dst[i + DAY] = (short) day;
		dst[i + MONTH] = (short) month;
		dst[i + YEAR] = (short) (year % 100);
		return dst;
	}

	private static short absYear(final int relative)
	{
		if (relative > 99)
			throw new KNXIllegalArgumentException("relative year out of range [0..99]");
		return (short) (relative + (relative < 90 ? 2000 : 1900));
	}
}
