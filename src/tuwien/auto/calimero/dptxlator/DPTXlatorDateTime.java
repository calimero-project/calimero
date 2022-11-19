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

import static java.lang.System.Logger.Level.WARNING;

import java.time.DateTimeException;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.Month;
import java.time.MonthDay;
import java.time.format.TextStyle;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.StringTokenizer;
import java.util.stream.IntStream;

import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;

/**
 * Translator for KNX DPTs with main number 19, type <b>date with time</b>.
 * The KNX data type width is 8 bytes, and contains
 * <ul>
 * <li> date information: month, day of month, day of week</li>
 * <li>time information: hour, minute, second</li>
 * <li>additional time information: working day, daylight saving time (DST), and</li>
 * <li>clock information: faulty clock, external clock synchronization signal.</li>
 * </ul>
 * The field usage of working day, year, date, time, and day of week is optional.<br>
 * By default, on setting date/time information, only general range checks are performed, no check is done whether the
 * information corresponds to a valid calendar time (see {@link #validate()}. All field-methods behave in non-lenient
 * time value mode, i.e., no value overflow is allowed and values are not normalized or adjusted using the next, larger
 * field. For example, February 29<sup>th</sup> will not result in March 1<sup>st</sup> on no leap year.<br>
 * This type permits the hour set to 24 (with minute and second only valid if 0), representing midnight of the old day,
 * to handle time information used in schedule programs.
 * <p>
 * The default return value after creation is the calendar value equal to {@code 1900/1/1 00:00:00} (year/month/day
 * hh:mm:ss), no clock fault, not in daylight saving time, no external clock synchronization signal, day of week and
 * working day fields are not used.
 * <p>
 * The methods {@link #setValue(String)} and {@link #setValues(String[])} support the following information in
 * addition to date/time information:
 * <ul>
 * <li>indicate external clock synchronization: use "sync"; the default is no external clock synchronization</li>
 * <li>daylight saving time: use "DST" to indicate daylight saving time; the default is no DST</li>
 * <li>working day or holiday (no working day): use "workday" to mark date as working day, and "holiday" to mark date as
 * (bank) holiday; by default, working day information is not used</li>
 * </ul>
 *
 * @author B. Malinowsky
 */
public class DPTXlatorDateTime extends DPTXlator
{
	public static final String Description = "Date with Time";

	/**
	 * DPT ID 19.001, Date with time; values from <b>1900/01/01 00:00:00</b> to <b>2155/12/31 24:00:00</b>.
	 */
	public static final DPT DPT_DATE_TIME = new DPT("19.001", "Date with time", "1900/01/01 00:00:00",
			"2155/12/31 24:00:00", "yr/mth/day hr:min:sec");

	/**
	 * Field number for {@code get} and {@code set} indicating whether the
	 * year field is used.
	 *
	 * @see #setValidField(int, boolean)
	 * @see #isValidField(int)
	 */
	public static final int YEAR = 0;

	/**
	 * Field number for {@code get} and {@code set} indicating whether the
	 * date field (month and day of month) is used.
	 *
	 * @see #setValidField(int, boolean)
	 * @see #isValidField(int)
	 */
	public static final int DATE = 1;

	/**
	 * Field number for {@code get} and {@code set} indicating whether the
	 * time field (hour, minute and second) is used.
	 *
	 * @see #setValidField(int, boolean)
	 * @see #isValidField(int)
	 */
	public static final int TIME = 2;

	/**
	 * Field number for {@code get} and {@code set} indicating whether the
	 * day of week field is used.
	 *
	 * @see #setValidField(int, boolean)
	 * @see #isValidField(int)
	 */
	public static final int DAY_OF_WEEK = 3;

	/**
	 * Field number for {@code get} and {@code set} indicating whether the working day field is used.
	 * <p>
	 * Working day information can be specified in string values by using "workday" to denote a working day, or
	 * "holiday" to denote a (bank) holiday (no working day).
	 *
	 * @see #setValidField(int, boolean)
	 * @see #isValidField(int)
	 */
	public static final int WORKDAY = 4;

	/**
	 * Field number to query or change the daylight saving time (DST) information.
	 * <p>
	 * This field is for user information solely, any DST offset is already considered in
	 * the time field (i.e., the hour field contains the adjusted value).
	 * <p>
	 * If daylight saving time is used, this information can be specified in string values
	 * by using "DST" to denote daylight saving time.
	 *
	 * @see #setDateTimeFlag(int, boolean)
	 * @see #getDateTimeFlag(int)
	 */
	private static final int DAYLIGHT = 5;

	/**
	 * Minimum year representable by this type, year = {@value #MIN_YEAR}.
	 */
	public static final int MIN_YEAR = 1900;

	/**
	 * Maximum year representable by this type, year = {@value #MAX_YEAR}.
	 */
	public static final int MAX_YEAR = MIN_YEAR + 0xff;

	private static final int MONTH = 1;
	private static final int DAY = 2;
	private static final int HOUR = 3;
	private static final int MINUTE = 4;
	private static final int SECOND = 5;
	private static final int DOW = 6;

	private static final String DAYLIGHT_SIGN = "DST";
	private static final String WORKDAY_SIGN = "workday";
	private static final String HOLIDAY_SIGN = "holiday";
	private static final String SYNC_SIGN = "sync";

	private static final String[] DAYS = { "Any day", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
	private static final String[] FIELDS = { "year", "month", "day", "hour", "minute", "second" };
	private static final int[] MIN_VALUES = { MIN_YEAR, 1, 1, 0, 0, 0, 0 };
	private static final int[] MAX_VALUES = { MAX_YEAR, 12, 31, 24, 59, 59, 7 };

	// standard field bit masks
	private static final int DST = 0x01;
	private static final int NO_TIME = 0x02;
	private static final int NO_DOW = 0x04;
	private static final int NO_DATE = 0x08;
	private static final int NO_YEAR = 0x10;
	private static final int NO_WD = 0x20;
	private static final int WD = 0x40;
	private static final int FAULT = 0x80;
	// extended field bit masks
	private static final int QUALITY = 0x80;
	private static final int SyncSourceReliability = 0x40;

	private static final int[] FIELD_MASKS = { NO_YEAR, NO_DATE, NO_TIME, NO_DOW, NO_WD };

	// fault, workday, DST, quality
	private static final int[] FLAG_MASKS = { WD, DST, FAULT, QUALITY };

	private static final short[] defaultData = { 0, 1, 1, 0, 0, 0, NO_WD | NO_DOW, 0 };

	private static Calendar c;
	private static final Map<String, DPT> types;
	static {
		types = new HashMap<>(3);
		types.put(DPT_DATE_TIME.getID(), DPT_DATE_TIME);
	}

	private boolean extFormat = true;

	/**
	 * Creates a translator for DPT ID 19.001, date with time.
	 */
	public DPTXlatorDateTime() {
		super(8);
		dpt = DPT_DATE_TIME;
		data = defaultData.clone();
	}

	/**
	 * Creates a translator for the given datapoint type.
	 *
	 * @param dpt the requested datapoint type
	 * @throws KNXFormatException on not supported or not available DPT
	 */
	public DPTXlatorDateTime(final DPT dpt) throws KNXFormatException
	{
		this(dpt.getID());
	}

	/**
	 * Creates a translator for the given datapoint type ID.
	 *
	 * @param dptID available implemented datapoint type ID
	 * @throws KNXFormatException on wrong formatted or not expected (available) {@code dptID}
	 */
	public DPTXlatorDateTime(final String dptID) throws KNXFormatException
	{
		super(8);
		setTypeID(types, dptID);
		data = defaultData.clone();
	}

	@Override
	public String[] getAllValues()
	{
		final String[] buf = new String[data.length / 8];
		for (int i = 0; i < buf.length; ++i)
			buf[i] = fromDPT(i);
		return buf;
	}

	/**
	 * Sets year, month and day of month information of the first date/time item.
	 * <p>
	 * This method does not reset other item data or discard other translation items.
	 *
	 * @param year year value, 1900 &lt;= year &lt;= 2155
	 * @param month month value, 1 &lt;= month &lt;= 12
	 * @param day day value, 1 &lt;= day &lt;= 31
	 */
	public final void setDate(final int year, final int month, final int day)
	{
		set(data, 0, YEAR, year);
		set(data, 0, MONTH, month);
		set(data, 0, DAY, day);
	}

	/**
	 * Returns the year information.
	 *
	 * @return year value, 0 &lt;= second &lt;= 59
	 */
	public final short getYear()
	{
		return (short) (data[YEAR] + MIN_YEAR);
	}

	/**
	 * Returns the month information.
	 *
	 * @return month value, 0 &lt; month &lt;= 12, might be 0 on unused field
	 */
	public final int getMonth()
	{
		return data[MONTH];
	}

	/**
	 * @return month-of-year if month information is available
	 * @throws DateTimeException if month information is 0
	 */
	public final Month month() { return Month.of(getMonth()); }

	/**
	 * Returns the day of month information.
	 * <p>
	 * The first day of month equals 1.<br>
	 *
	 * @return day value, 0 &lt; day &lt;= 31, might be 0 on unused field
	 */
	public final int getDay()
	{
		return data[DAY];
	}

	/**
	 * Sets the day of week of the first date/time item.
	 * <p>
	 * A day of week value of 0 corresponds to "any day", indicating the day of week is
	 * variable (used in scheduling). The first day of week is Monday with a value of 1.
	 * <br>
	 * This method does not reset other item data or discard other translation items.
	 *
	 * @param day day of week value, 0 &lt;= day &lt;= 7
	 */
	public final void setDayOfWeek(final int day)
	{
		set(data, 0, DOW, day);
	}

	/**
	 * Returns the day of week information.
	 * <p>
	 * The return of 0 corresponds to "any day", indicating the day of week is variable
	 * (used in scheduling). The first day of week is Monday with a value of 1.
	 *
	 * @return day of week value, 0 &lt;= day of week &lt;= 7
	 */
	public final int getDayOfWeek()
	{
		return data[3] >> 5;
	}

	/**
	 * @return day of the week if day-of-week is set, empty if no day was set (any day)
	 */
	public final Optional<DayOfWeek> dayOfWeek() {
		final int dayOfWeek = getDayOfWeek();
		return dayOfWeek == 0 ? Optional.empty() : Optional.of(DayOfWeek.of(dayOfWeek));
	}

	/**
	 * @return the month-day if date information is available
	 * @throws DateTimeException if day is 0 or day-of-month is invalid for the month
	 */
	public final MonthDay monthDay() { return MonthDay.of(getMonth(), getDay()); }

	/**
	 * Sets the hour, minute and second information for the first date/time item.
	 * <p>
	 * On a hour value of 24, values of minute and second have to be 0.<br>
	 * This method does not reset other item data or discard other translation items.
	 *
	 * @param hour hour value, 0 &lt;= hour &lt;= 24
	 * @param minute minute value, 0 &lt;= minute &lt;= 59
	 * @param second second value, 0 &lt;= second &lt;= 59
	 */
	public final void setTime(final int hour, final int minute, final int second)
	{
		if (!check24Hours(hour, minute, second))
			throw new KNXIllegalArgumentException("incorrect time");
		set(data, 0, HOUR, hour);
		set(data, 0, MINUTE, minute);
		set(data, 0, SECOND, second);
	}

	/**
	 * Returns the hour information.
	 * <p>
	 * An hour value of 24 represents midnight of the old day, the corresponding minute
	 * and second are always 0.
	 *
	 * @return hour value, 0 &lt;= hour &lt;= 24
	 */
	public final int getHour()
	{
		return data[HOUR] & 0x1F;
	}

	/**
	 * Returns the minute information.
	 * <p>
	 *
	 * @return minute value, 0 &lt;= minute &lt;= 59
	 */
	public final int getMinute()
	{
		return data[MINUTE];
	}

	/**
	 * Returns the second information.
	 * <p>
	 *
	 * @return second value, 0 &lt;= second &lt;= 59
	 */
	public final int getSecond()
	{
		return data[SECOND];
	}

	/**
	 * Sets the year, date, time, and day-of-week information for the first date/time item.
	 * Working day information is set to not valid ({@link #isValidField(int)} with {@link #WORKDAY} returns
	 * {@code false}). Daylight saving time is always {@code false}.
	 *
	 * @param dateTime local date-time to set
	 */
	public void setValue(final LocalDateTime dateTime) {
		data = new short[8];
		set(data, 0, YEAR, dateTime.getYear());
		set(data, 0, MONTH, dateTime.getMonthValue());
		set(data, 0, DAY, dateTime.getDayOfMonth());
		set(data, 0, HOUR, dateTime.getHour());
		set(data, 0, MINUTE, dateTime.getMinute());
		set(data, 0, SECOND, dateTime.getSecond());
		set(data, 0, DOW, dateTime.getDayOfWeek().getValue());
		data[6] |= NO_WD;
	}

	@Override
	public void setValue(final double milliseconds) {
		setValue((long) milliseconds);
	}

	/**
	 * Sets the date/time for the first date/time item using UTC millisecond information.
	 * <p>
	 * Following fields are set: year, month, day, day of week, hour, minute, second,
	 * daylight time. All according fields are set to used state.<br>
	 * The {@code value} is interpreted by a calendar obtained by
	 * {@link Calendar#getInstance()}.<br>
	 * The new value item replaces any other items contained in this translator.
	 *
	 * @param milliseconds time value in milliseconds, as used by {@link Calendar}
	 */
	public final void setValue(final long milliseconds)
	{
		initCalendar();
		synchronized (c) {
			c.clear();
			c.setTimeInMillis(milliseconds);
			data = new short[8];
			set(data, 0, YEAR, c.get(Calendar.YEAR));
			set(data, 0, MONTH, c.get(Calendar.MONTH) + 1);
			set(data, 0, DAY, c.get(Calendar.DAY_OF_MONTH));
			set(data, 0, HOUR, c.get(Calendar.HOUR_OF_DAY));
			set(data, 0, MINUTE, c.get(Calendar.MINUTE));
			set(data, 0, SECOND, c.get(Calendar.SECOND));
			final int dow = c.get(Calendar.DAY_OF_WEEK);
			set(data, 0, DOW, dow == Calendar.SUNDAY ? 7 : dow - 1);
			setBit(0, DST, c.get(Calendar.DST_OFFSET) != 0);
			data[6] |= NO_WD;
		}
	}

	/**
	 * Returns the date and time information of the first date/time item in UTC
	 * milliseconds, using the system default {@link Calendar}.
	 * <p>
	 * The method uses the year, month, day, DST and, optionally, hour, minute, second and
	 * day of week field for calculation.<br>
	 * On unused time field, 00:00:00 is used. If year, month or day field is unused (see
	 * {@link #isValidField(int)}, or the field values do not represent a valid calendar
	 * time, an exception is thrown. If time equals 24:00:00, it is represented as
	 * 23:59:59.999, since the time ambiguity of midnight is resolved as midnight
	 * belonging to the next day (00:00:00) in the used calendar. However, no field values
	 * itself is changed permanently.<br>
	 * The used calendar is obtained by {@link Calendar#getInstance()}, and the
	 * calculation is done in non-lenient mode.
	 *
	 * @return the date/time in milliseconds as long,
	 * @throws KNXFormatException on required, but not set fields, if date/time
	 *         information does not represent a valid calendar time
	 */
	public final long getValueMilliseconds() throws KNXFormatException
	{
		return fromDPTMilliseconds(0);
	}

	/**
	 * Returns the local date-time information of the first translation item if year, date, and optionally time
	 * information is available.
	 * Workday, day of week, and daylight saving time information is ignored.
	 *
	 * @return local date/time object
	 * @throws KNXFormatException on faulty clock, missing year or date information
	 * @throws DateTimeException on a problem calculating date-time
	 */
	public final LocalDateTime localDateTime() throws KNXFormatException {
		return localDateTime(0);
	}

	private LocalDateTime localDateTime(final int index) throws KNXFormatException {
		if (isBitSet(index, FAULT))
			throw new KNXFormatException("faulty clock");
		if (!isValidField(index, YEAR) || !isValidField(index, DATE))
			throw new KNXFormatException("insufficient date information for local date-time");

		final var ld = LocalDate.of(getYear(), getMonth(), getDay());
		if (isValidField(index, TIME)) {
			// we use LocalTime.MAX for 24:00:00
			final boolean cheat = getHour() == 24;
			final var lt = cheat ? LocalTime.MAX : LocalTime.of(getHour(), getMinute(), getSecond());
			return LocalDateTime.of(ld, lt);
		}
		return LocalDateTime.of(ld, LocalTime.MIN);
	}

	/**
	 * Returns the date and time information of the first translation item in UTC milliseconds.
	 * This method uses the year, month, day, DST and, optionally, hour, minute, second and
	 * day of week field for calculation.
	 *
	 * @throws KNXFormatException on required, but not set fields, if date/time
	 *         information does not represent a valid calendar time
	 */
	@Override
	public double getNumericValue() throws KNXFormatException
	{
		return getValueMilliseconds();
	}

	/**
	 * Sets the clock fault information field of the first date/time item.
	 * <p>
	 * A clock fault indicates one or more corrupted date/time fields, for example due to power-down of the KNX
	 * device, a not configured clock, or no reception of synchronization message.
	 * <p>
	 * This method does not reset other item data or discard other translation items.
	 *
	 * @param faulty {@code true} if clock is faulty, {@code false} otherwise
	 */
	public final void setFaultyClock(final boolean faulty)
	{
		setBit(0, FAULT, faulty);
	}

	/**
	 * Returns whether the date/time information is marked as corrupted, to be checked before accessing further
	 * date/time information to assure correct values.
	 * <p>
	 * A clock fault indicates one or more corrupted date/time fields, for example due to power-down of the KNX
	 * device, a not configured clock, or no reception of synchronization message.
	 *
	 * @return {@code true} on clock fault, {@code false} otherwise
	 */
	public final boolean isFaultyClock()
	{
		return isBitSet(0, FAULT);
	}

	/**
	 * Sets an externally synchronized clock for the first date/time item.
	 *
	 * @param externalSync {@code true} if externally synchronized clock, {@code false} otherwise
	 */
	public final void setClockSync(final boolean externalSync)
	{
		setBitEx(0, QUALITY, externalSync);
	}

	/**
	 * Returns whether the clock reading used for the date/time information comes from an externally synchronized clock.
	 *
	 * @return {@code true} if clock uses external synchronization, {@code false} otherwise
	 */
	public final boolean isSyncClock()
	{
		return isBitSetEx(0, QUALITY);
	}

	/**
	 * Returns the synchronization source reliability of the clock.
	 *
	 * @return {@code true} if clock uses a reliable synchronisation source (radio, Internet), {@code false}
	 *         for unreliable synchronisation source (mains, local quartz)
	 */
	public final boolean isReliableSyncSource() { return isBitSetEx(0, SyncSourceReliability); }

	/**
	 * Sets working day information for the first date/time item.
	 *
	 * @param workday {@code true} to mark date as working day, {@code false} for holiday (no working day)
	 */
	public final void setWorkday(final boolean workday)
	{
		setValidField(WORKDAY, true);
		setBit(0, WD, workday);
	}

	/**
	 * @return {@code true} if date/time information is marked as working day, {@code false} for holiday (no
	 * working day)
	 */
	public final boolean isWorkday()
	{
		return getDateTimeFlag(0, WORKDAY);
	}

	/**
	 * Sets daylight saving time (DST) for the first date/time item; this setting does not affect any time field
	 * information.
	 *
	 * @param dst {@code true} if daylight saving time is used, {@code false} otherwise
	 */
	public final void setDst(final boolean dst)
	{
		setBit(0, DST, dst);
	}

	/**
	 * Returns whether time information is corrected for daylight saving time (DST).
	 *
	 * @return {@code true} if daylight saving time (DST) is used, {@code false} otherwise; any DST offset is
	 *         already considered for time, i.e., the hour field contains the already adjusted value
	 */
	public final boolean isDst()
	{
		return getDateTimeFlag(0, DAYLIGHT);
	}

	/**
	 * Sets a date/time field of the first translation item to valid or not valid.
	 * <p>
	 * A field which is valid, i.e., contains valid data, has to be set {@code true},
	 * otherwise the field should be set not valid with {@code false}.<br>
	 * Possible fields allowed to be set valid or not valid are {@link #YEAR},
	 * {@link #DATE}, {@link #TIME}, {@link #DAY_OF_WEEK} and {@link #WORKDAY}.
	 *
	 * @param field field number
	 * @param valid {@code true} if field is supported and contains valid data,
	 *        {@code false} otherwise
	 */
	public final void setValidField(final int field, final boolean valid)
	{
		if (field < 0 || field >= FIELD_MASKS.length)
			throw new KNXIllegalArgumentException("illegal field");
		setBit(0, FIELD_MASKS[field], !valid);
	}

	/**
	 * Returns whether a field is valid, i.e., supported and used for date/time
	 * information.
	 * <p>
	 * Only data of valid fields are required to be set or examined. A field set to not
	 * valid shall be ignored, it is not supported and contains no valid data.<br>
	 * Possible fields allowed to be set valid or not valid are {@link #YEAR},
	 * {@link #DATE}, {@link #TIME}, {@link #DAY_OF_WEEK} and {@link #WORKDAY}.
	 *
	 * @param field field number
	 * @return {@code true} if field is supported and in use, {@code false}
	 *         otherwise
	 */
	public final boolean isValidField(final int field)
	{
		if (field < 0 || field >= FIELD_MASKS.length)
			throw new KNXIllegalArgumentException("illegal field");
		return !isBitSet(0, FIELD_MASKS[field]);
	}

	/**
	 * Does a complete validity check on the contained date/time items.
	 * <p>
	 * An item is valid if all used fields correspond to a valid calendar time. The check
	 * is only performed if at least year and date fields are used.<br>
	 * After modifying date/time fields, this method has to be called again if validation
	 * is required.<br>
	 * It returns the result of the validity checks performed on the date/time items.
	 * <p>
	 * Comparison of the two kinds of validity:<br>
	 * When setting individual parts of a date/time, only the KNX requirements for the DPT
	 * are checked, as requested by the DPT specification. For example, this includes a
	 * common range check of a value. So set items always match these KNX value ranges.<br>
	 * This validation method checks if the date/time fields represent a valid calendar
	 * time, which is a much stronger requirement.
	 *
	 * @return {@code true} if date/times are valid, {@code false} otherwise
	 */
	public final boolean validate()
	{
		try {
			for (int i = 0; i < data.length / 8; ++i)
				if (isValidField(i, YEAR) && isValidField(i, DATE))
					fromDPTMilliseconds(i);
		}
		catch (final KNXFormatException e) {
			return false;
		}
		return true;
	}

	@Override
	public void setData(final byte[] data, final int offset)
	{
		if (offset < 0 || offset > data.length)
			throw new KNXIllegalArgumentException("illegal offset " + offset);
		final int size = (data.length - offset) & ~7;
		if (size == 0)
			throw new KNXIllegalArgumentException("DPT " + dpt.getID() + " " + dpt.getDescription() + ": data length "
					+ (data.length - offset) + " < required datapoint type width " + Math.max(1, getTypeSize()));
		final short[] buf = new short[size];
		final int[] mask = { 0xFF, 0x0F, 0x1F, 0xFF, 0x3F, 0x3F, 0xFF, 0xc0 };
		for (int i = 0; i < size; ++i) {
			final int field = i & 0x07;
			buf[i] = (short) (data[offset + i] & mask[field]);
			// check reserved bits
			if ((ubyte(data[offset + i]) & ~mask[field]) != 0)
				logger.log(WARNING, "DPT " + dpt.getID() + " " + dpt.getDescription() + ": reserved bit not 0");
			// check range on set fields
			if (field == 6 && (buf[i] & NO_DATE) == 0) {
				checkRange(MONTH, buf[i - 5]);
				checkRange(DAY, buf[i - 4]);
			}
			if (field == 6 && (buf[i] & NO_TIME) == 0) {
				checkRange(HOUR, buf[i - 3] & 0x1F);
				checkRange(MINUTE, buf[i - 2]);
				checkRange(SECOND, buf[i - 1]);
				if (!check24Hours(buf[i - 3] & 0x1F, buf[i - 2], buf[i - 1]))
					throw new KNXIllegalArgumentException("incorrect time");
			}
		}
		this.data = buf;
	}

	/**
	 * Specifies the formatting to use for date/time string representations returned by
	 * the translator.
	 * <p>
	 * A string in extended format contains all valid information of the date/time type.
	 * In extended format, additionally the day of week, daylight time, working day and clock
	 * synchronization signal information is considered in the output format. Otherwise,
	 * these fields are always ignored, i.e, only clock fault, year, month, day, hour,
	 * minute and second will get used, if valid.
	 * <p>
	 * The used format is extended by default.
	 *
	 * @param extended string format to use, {@code true} for extended format
	 */
	public final void useValueFormat(final boolean extended)
	{
		extFormat = extended;
	}

	@Override
	public Map<String, DPT> getSubTypes()
	{
		return types;
	}

	/**
	 * @return the subtypes of the date with time translator type
	 * @see DPTXlator#getSubTypesStatic()
	 */
	protected static Map<String, DPT> getSubTypesStatic()
	{
		return types;
	}

	private static void checkRange(final int field, final int v)
	{
		if (v < MIN_VALUES[field] || v > MAX_VALUES[field])
			throw new KNXIllegalArgumentException(FIELDS[field] + " out of range: " + v);
	}

	// check on hour = 24, minutes and seconds have to be 0
	private static boolean check24Hours(final int hr, final int min, final int sec)
	{
		if (hr != 24 || min == 0 && sec == 0)
			return true;
		return false;
	}

	private String fromDPT(final int index)
	{
		if (isBitSet(index, FAULT))
			return "corrupted date/time";
		final StringBuilder sb = new StringBuilder(20);
		final int i = index * 8;
		// year
		if (!isBitSet(index, NO_YEAR))
			sb.append(data[i] + MIN_YEAR);
		if (!isBitSet(index, NO_DATE)) {
			// month
			sb.append('/').append(data[i + 1]);
			// day
			sb.append('/').append(data[i + 2]);
		}
		if (extFormat) {
			if (!isBitSet(index, NO_DOW)) {
				sb.append(", ");
				final int dayOfWeek = data[i + 3] >> 5;
				if (dayOfWeek == 0)
					sb.append("any day");
				else {
					final var displayName = localizedDayOfWeek(dayOfWeek);
					sb.append(displayName);
				}
			}
			if (!isBitSet(index, NO_WD))
				sb.append(" (").append(isBitSet(index, WD) ? WORKDAY_SIGN : HOLIDAY_SIGN).append(')');
		}
		if (!isBitSet(index, NO_TIME)) {
			// hr:min:sec
			sb.append(' ').append(data[i + 3] & 0x1F);
			sb.append(':').append(data[i + 4]).append(':').append(data[i + 5]);
			// daylight saving time
			if (extFormat && isBitSet(index, DST))
				sb.append(' ').append(DAYLIGHT_SIGN);
		}
		if (extFormat && isBitSetEx(index, QUALITY))
			sb.append(" (" + SYNC_SIGN + ")");
		return sb.toString();
	}

	private static String localizedDayOfWeek(final int dayOfWeek) {
		return DayOfWeek.of(dayOfWeek).getDisplayName(TextStyle.SHORT, Locale.getDefault());
	}

	private long fromDPTMilliseconds(final int index) throws KNXFormatException
	{
		if (isBitSet(index, FAULT) || !isValidField(index, YEAR) || !isValidField(index, DATE))
			throw new KNXFormatException("insufficient information for calendar");
		initCalendar();
		final int i = index * 8;
		synchronized (c) {
			c.clear();
			c.set(data[i] + MIN_YEAR, data[i + 1] - 1, data[i + 2]);
			if (isValidField(index, TIME)) {
				// we use 23:59:59.999 in calendar for 24:00:00
				final boolean cheat = (data[i + 3] & 0x1F) == 24;
				c.set(Calendar.HOUR_OF_DAY, cheat ? 23 : data[i + 3] & 0x1F);
				c.set(Calendar.MINUTE, cheat ? 59 : data[i + 4]);
				c.set(Calendar.SECOND, cheat ? 59 : data[i + 5]);
				if (cheat)
					c.set(Calendar.MILLISECOND, 999);
			}
			try {
				final long ms = c.getTimeInMillis();
				if (isValidField(index, DAY_OF_WEEK)) {
					int day = c.get(Calendar.DAY_OF_WEEK);
					day = day == Calendar.SUNDAY ? 7 : day - 1;
					if ((data[i + 3] >> 5) != day)
						throw new KNXFormatException("differing day of week");
				}
				if (getDateTimeFlag(index, DAYLIGHT) != (c.get(Calendar.DST_OFFSET) != 0))
					throw new KNXFormatException("differing daylight saving time");
				return ms;
			}
			catch (final IllegalArgumentException e) {
				throw new KNXFormatException("invalid calendar value", e.getMessage());
			}
		}
	}

	private boolean getDateTimeFlag(final int index, final int field)
	{
		final int f = field - WORKDAY;
		if (f < 0 || f >= FLAG_MASKS.length)
			throw new KNXIllegalArgumentException("illegal field");
		return isBitSet(index, FLAG_MASKS[f]);
	}

	private boolean isValidField(final int index, final int field)
	{
		return !isBitSet(index, FIELD_MASKS[field]);
	}

	private boolean isBitSet(final int index, final int mask)
	{
		return (data[8 * index + 6] & mask) != 0;
	}

	private boolean isBitSetEx(final int index, final int mask)
	{
		return (data[8 * index + 7] & mask) != 0;
	}

	private static void set(final short[] dst, final int index, final int field, final int v)
	{
		checkRange(field, v);
		final int i = 8 * index + field;
		if (field == YEAR)
			dst[i] = (short) (v - MIN_YEAR);
		else if (field == DOW)
			// NOTE: DoW id is not field index
			dst[i - 3] = (short) (v << 5 | (dst[i - 3] & 0x1F));
		else if (field == HOUR)
			dst[i] = (short) (v | (dst[i] & 0xE0));
		else
			dst[i] = (short) v;
	}

	private void setBit(final int index, final int mask, final boolean bit)
	{
		setBit(data, index, mask, bit);
	}

	private static void setBit(final short[] dst, final int index, final int mask, final boolean bit)
	{
		if (bit)
			dst[8 * index + 6] |= mask;
		else
			dst[8 * index + 6] &= ~mask;
	}

	private void setBitEx(final int index, final int mask, final boolean bit)
	{
		setBitEx(data, index, mask, bit);
	}

	private static void setBitEx(final short[] v, final int index, final int mask, final boolean bit)
	{
		if (bit)
			v[8 * index + 7] |= mask;
		else
			v[8 * index + 7] &= ~mask;
	}

	// dst is assumed to be cleared
	@Override
	protected void toDPT(final String value, final short[] dst, final int index) throws KNXFormatException
	{
		// don't tokenize on dot, which is used in some localized day-of-week abbreviations and in German dates
		final StringTokenizer t = new StringTokenizer(value, ":-/ (,)");
		final int k = 8 * index;
		// dpt fields: | yr | mth | day | doW, hr | min | sec | dst, wd | sync, src |
		// mark all fields not used
		dst[k + 6] = NO_WD | NO_YEAR | NO_DATE | NO_DOW | NO_TIME;

		int sync = 0;
		int day = 0;
		int workingDay = 0;
		final int maxTokens = 10;
		final short[] numbers = new short[maxTokens];
		int count = 0;
		// parse whole string, only handle word and year tokens, store numbers
		for (int i = 0; i < maxTokens && t.hasMoreTokens(); ++i) {
			final String s = t.nextToken();
			try {
				// split on dots to recognize German date
				final String[] noDots = s.split("\\.");
				for (final var v : noDots) {
					final short no = Short.parseShort(v);
					if (no < 0)
						throw newException("negative date/time " + s, s);
					if (no >= MIN_YEAR && no <= MAX_YEAR) {
						set(dst, index, YEAR, no);
						setBit(dst, index, NO_YEAR, false);
					}
					else
						numbers[count++] = no;
				}
			}
			catch (final NumberFormatException e) {
				// parse number failed, check for word token
				if (s.equalsIgnoreCase(DAYLIGHT_SIGN))
					setBit(dst, index, DST, true);
				else if (s.equalsIgnoreCase(WORKDAY_SIGN) || s.equalsIgnoreCase(HOLIDAY_SIGN)) {
					if (++workingDay > 1) {
						final boolean wd = (dst[k + 6] & WD) != 0;
						throw newException("working day information already set to "
								+ (wd ? "'working day'" : ("'" + HOLIDAY_SIGN + "'")), s);
					}
					setBit(dst, index, NO_WD, false);
					setBit(dst, index, WD, s.equalsIgnoreCase(WORKDAY_SIGN));
				}
				else if (s.equalsIgnoreCase(SYNC_SIGN)) {
					if (++sync > 1)
						throw newException("duplicate flag", s);
					setBitEx(dst, index, QUALITY, true);
				}
				else if (++day == 1) {
					final String prefix = s.toLowerCase();
					final var optDow = IntStream.range(1, 8).filter(n -> localizedDayOfWeek(n).equalsIgnoreCase(prefix)).findFirst();
					if (optDow.isPresent())
						set(dst, index, DOW, optDow.getAsInt());
					else {
						int dow = DAYS.length - 1;
						while (dow >= 0 && !DAYS[dow].toLowerCase().startsWith(prefix))
							--dow;
						final boolean anyday = dow == 0 && t.hasMoreTokens() && t.nextToken().equalsIgnoreCase("day");
						if (dow <= 0 && !anyday)
							throw newException("wrong weekday", s, null);
						set(dst, index, DOW, dow);
					}

					setBit(dst, index, NO_DOW, false);
				}
				else
					throw newException("wrong date/time " + s, s, null);
			}
		}
		// find out date/time combination, and store numbers into fields
		if (count == 0)
			return;
		if (count == 1 || count == 4)
			throw newException("ambiguous date/time", value);
		int field = count == 3 ? HOUR : MONTH;
		if (field == HOUR || count == 5)
			setBit(dst, index, NO_TIME, false);
		if (field == MONTH)
			setBit(dst, index, NO_DATE, false);
		for (int i = 0; i < count; ++i, ++field)
			set(dst, index, field, numbers[i]);
		// check time field, if set
		if (field == SECOND + 1 && !check24Hours(numbers[count - 3], numbers[count - 2], numbers[count - 1]))
			throw newException("incorrect time", value);
	}

	private static synchronized void initCalendar()
	{
		if (c == null) {
			c = Calendar.getInstance();
			c.setLenient(false);
		}
	}
}
