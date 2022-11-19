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

import static java.time.temporal.ChronoField.DAY_OF_WEEK;

import java.lang.System.Logger.Level;
import java.time.DateTimeException;
import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;

/**
 * Translator for KNX DPTs with main number 10, type <b>time</b>.
 * <p>
 * The KNX data type width is 3 bytes.<br>
 * The type contains time information (hour, minute, second), together with an (optional) day of week. If no day of week
 * is supplied or available, the value encoding "no-day" can be used; this identifier is optional. When applying Java
 * user-defined time formats, the "no-day" identifier is not a supported time format symbol, but is specific to the KNX
 * DPT. Short day name values are used for each day of the week (Mon, Tue, Wed, Thu, Fri, Sat, Sun). Time calculation is
 * based on the system default time zone and locale. All time information behaves in non-lenient mode, i.e., no value
 * overflow is allowed and values are not normalized or adjusted using the next, larger field.<br>
 * <p>
 * The default return value after creation is {@code 00:00:00}.
 *
 * @author B. Malinowsky
 */
public class DPTXlatorTime extends DPTXlator
{
	/**
	 * DPT ID 10.001, Time of day; values from <b>no-day, 00:00:00</b> to <b>Sun, 23:59:59</b>.
	 */
	public static final DPT DPT_TIMEOFDAY = new DPT("10.001", "Time of day", "no-day, 00:00:00", "Sun, 23:59:59",
			"dow, hh:mm:ss");

	private static final int DOW = 0;
	private static final int HOUR = 0;
	private static final int MINUTE = 1;
	private static final int SECOND = 2;

	private static final Map<Long, String> dow = new HashMap<>();

	// strict resolver style is default for ISO_TIME
	private static final ResolverStyle defaultResolverStyle = ResolverStyle.STRICT;
	static final DateTimeFormatterBuilder builder;
	private static volatile DateTimeFormatter dtf;

	private static final Map<String, DPT> types;

	static {
		types = new HashMap<>(3);
		types.put(DPT_TIMEOFDAY.getID(), DPT_TIMEOFDAY);

		dow.put(0L, "no-day");
		dow.put(1L, "Mon");
		dow.put(2L, "Tue");
		dow.put(3L, "Wed");
		dow.put(4L, "Thu");
		dow.put(5L, "Fri");
		dow.put(6L, "Sat");
		dow.put(7L, "Sun");

		//@formatter:off
		builder = new DateTimeFormatterBuilder().parseCaseInsensitive().parseStrict()
				.optionalStart().appendText(DAY_OF_WEEK, dow)
					.optionalStart().appendLiteral(',').optionalEnd()
					.appendLiteral(' ')
				.optionalEnd()
				.append(DateTimeFormatter.ISO_TIME);
		//@formatter:off
		dtf = builder.toFormatter();
	}

	/**
	 * Creates a translator for DPT ID 10.001, time of day.
	 */
	public DPTXlatorTime() {
		super(3);
		dpt = DPT_TIMEOFDAY;
	}

	/**
	 * Creates a translator for the given datapoint type.
	 *
	 * @param dpt the requested datapoint type
	 * @throws KNXFormatException on not supported or not available DPT
	 */
	public DPTXlatorTime(final DPT dpt) throws KNXFormatException
	{
		this(dpt.getID());
	}

	/**
	 * Creates a translator for the given datapoint type ID.
	 *
	 * @param dptId available implemented datapoint type ID
	 * @throws KNXFormatException on wrong formatted or not expected (available) {@code dptID}
	 */
	public DPTXlatorTime(final String dptId) throws KNXFormatException
	{
		super(3);
		setTypeID(types, dptId);
	}

	/**
	 * Sets a user defined time value format used by all instances of this class.
	 * <p>
	 * The pattern is specified according to {@link DateTimeFormatter}. Subsequent time information, supplied and
	 * returned in textual representation, will be parsed/formatted according to this pattern. Note, the format will
	 * rely on calendar default time symbols (i.e., language for example), and does not support the KNX DPT identifier
	 * "no-day" for day of week. This identifier can not be used therefore.
	 *
	 * @param pattern the new pattern specifying the value time format
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

	/**
	 * Sets the day of week, hour, minute and second information for the first time item.
	 * <p>
	 * Any other items in the translator are discarded on successful set.<br>
	 * A day of week value of 0 corresponds to "no-day", indicating the day of week is not used. The first day of week
	 * is Monday with a value of 1, the last day is Sunday with a value of 7. <br>
	 *
	 * @param dayOfWeek day of week, 0 &lt;= day &lt;= 7
	 * @param hour hour value, 0 &lt;= hour &lt;= 23
	 * @param minute minute value, 0 &lt;= minute &lt;= 59
	 * @param second second value, 0 &lt;= second &lt;= 59
	 */
	public final void setValue(final int dayOfWeek, final int hour, final int minute, final int second)
	{
		data = set(dayOfWeek, hour, minute, second, new short[3], 0);
	}

	/**
	 * Returns the day of week information.
	 * <p>
	 * The return of 0 corresponds to "no-day", indicating the day of week is not used. The first day of week is Monday
	 * with a value of 1, Sunday has a value of 7.
	 *
	 * @return day of week value, 0 &lt;= day of week &lt;= 7
	 */
	public final int getDayOfWeek()
	{
		return data[DOW] >> 5;
	}

	/**
	 * @return the {@link DayOfWeek} of the first translation item, empty if no day was set
	 */
	public Optional<DayOfWeek> dayOfWeek() {
		final int dayOfWeek = getDayOfWeek();
		return dayOfWeek == 0 ? Optional.empty() : Optional.of(DayOfWeek.of(dayOfWeek));
	}

	/**
	 * Returns the hour information.
	 *
	 * @return hour value, 0 &lt;= hour &lt;= 23
	 */
	public final int getHour()
	{
		return data[HOUR] & 0x1F;
	}

	/**
	 * Returns the minute information.
	 *
	 * @return minute value, 0 &lt;= minute &lt;= 59
	 */
	public final int getMinute()
	{
		return data[MINUTE];
	}

	/**
	 * Returns the second information.
	 *
	 * @return second value, 0 &lt;= second &lt;= 59
	 */
	public final int getSecond()
	{
		return data[SECOND];
	}

	/**
	 * @return the local time obtained from hour, minute, and second of the first translation item
	 * @throws DateTimeException if the value of any field is out of range
	 */
	public final LocalTime localTime()
	{
		return localTime(0);
	}

	@Override
	public void setValue(final double milliseconds) {
		setValue((long) milliseconds);
	}

	/**
	 * Sets the time for the first item using UTC millisecond information.
	 *
	 * @param milliseconds time value in milliseconds from the epoch
	 */
	public final void setValue(final long milliseconds)
	{
		data = toDPT(milliseconds, new short[3], 0);
	}

	/**
	 * Returns the time information in UTC milliseconds, using hour, minute, and second information. Note, since this is
	 * UTC time information, the initially returned local time 00:00:00 does therefore not corresponding to 0
	 * milliseconds, except in the case when the local time zone is GMT.
	 *
	 * @return the time in milliseconds as long, as used in {@link Calendar}
	 */
	public final long getValueMilliseconds()
	{
		return fromDPTMillis(0);
	}

	@Override
	public double getNumericValue()
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
			set((data[i + DOW] & 0xE0) >> 5, data[i + HOUR] & 0x1F, data[i + MINUTE] & 0x3F, data[i + SECOND] & 0x3F,
					buf, item++);
			// check reserved bits
			if ((data[i + MINUTE] & ~0x3F) + (data[i + SECOND] & ~0x3F) != 0)
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
	 * @return the subtypes of the time translator type
	 * @see DPTXlator#getSubTypesStatic()
	 */
	protected static Map<String, DPT> getSubTypesStatic()
	{
		return types;
	}

	private String fromDPT(final int index)
	{
		final int i = index * 3;
		final int day = data[i + DOW] >> 5;
		final String prefix = day == 0 ? "" : dow.get((long) day) + ", ";
		return prefix + dtf.format(localTime(index));
	}

	private long fromDPTMillis(final int index)
	{
		return ZonedDateTime.now().with(localTime(index)).toInstant().toEpochMilli();
	}

	private LocalTime localTime(final int index)
	{
		final int i = index * 3;
		final int h = data[i + HOUR] & 0x1F;
		final int m = data[i + MINUTE];
		final int s = data[i + SECOND];
		return LocalTime.of(h, m, s);
	}

	@Override
	protected void toDPT(final String value, final short[] dst, final int index) throws KNXFormatException
	{
		try {
			final TemporalAccessor time = dtf.parse(value.trim());
			final long dow = time.isSupported(DAY_OF_WEEK) ? time.getLong(ChronoField.DAY_OF_WEEK) : 0;
			final int h = time.get(ChronoField.HOUR_OF_DAY);
			final int m = time.get(ChronoField.MINUTE_OF_HOUR);
			final int s = time.get(ChronoField.SECOND_OF_MINUTE);
			set((int) dow, h, m, s, dst, index);
		}
		catch (final DateTimeParseException e) {
			throw newException("invalid time", value, e);
		}
	}

	private static short[] toDPT(final long milliseconds, final short[] dst, final int index)
	{
		final ZonedDateTime atZone = Instant.ofEpochMilli(milliseconds).atZone(ZoneId.systemDefault());
		final LocalTime time = atZone.toLocalTime();
		set(atZone.getDayOfWeek().getValue(), time.getHour(), time.getMinute(), time.getSecond(), dst, index);
		return dst;
	}

	private static short[] set(final int dow, final int hour, final int minute, final int second, final short[] dst,
		final int index)
	{
		if (dow < 0 || dow > 7)
			throw new KNXIllegalArgumentException("day of week out of range [0..7]");
		if (hour < 0 || hour > 23)
			throw new KNXIllegalArgumentException("hour out of range [0..23]");
		if (minute < 0 || minute > 59)
			throw new KNXIllegalArgumentException("minute out of range [0..59]");
		if (second < 0 || second > 59)
			throw new KNXIllegalArgumentException("second out of range [0..59]");
		final int i = 3 * index;
		dst[i + DOW] = (short) (dow << 5 | hour);
		dst[i + MINUTE] = (short) minute;
		dst[i + SECOND] = (short) second;
		return dst;
	}
}
