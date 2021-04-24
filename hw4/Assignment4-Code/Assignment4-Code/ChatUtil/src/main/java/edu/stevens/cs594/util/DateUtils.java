package edu.stevens.cs594.util;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

public class DateUtils {
	
	private static final String TAG = DateUtils.class.getCanonicalName();
	private static final Logger logger = Logger.getLogger(TAG);
	
	public static final long ONE_HOUR = 60 * 60 * 1000;
	public static final long ONE_DAY = 24 * ONE_HOUR;
	
	private DateUtils() {}
	
	public static void writeTimestamp(Timestamp timestamp, DataOutput out) {
		try {
			out.writeLong(timestamp == null ? 0 : timestamp.getTime());
		} catch (IOException e) {
			logger.log(Level.SEVERE, "IO Exception while writing data to storage: ", e);
		}
	}
	
	public static Timestamp readTimestamp(DataInput in) {
		try {
			long time = in.readLong();
			return time == 0 ? null : new Timestamp(time);
		} catch (IOException e) {
			logger.log(Level.SEVERE, "IO Exception while reading data from storage: ", e);
			return null;
		}
	}
	
	public static void writeDate(Date date, DataOutput out) {
		try {
			out.writeLong(date == null ? 0 : date.getTime());
		} catch (IOException e) {
			logger.log(Level.SEVERE, "IO Exception while writing data to storage: ", e);
		}
	}
	
	public static Date readDate(DataInput in) {
		try {
			long time = in.readLong();
			return time == 0 ? null : new Date(time);
		} catch (IOException e) {
			logger.log(Level.SEVERE, "IO Exception while reading data from storage: ", e);
			return null;
		}
	}
	
	public static long putDate(Date date) {
		return date == null ? 0 : date.getTime();
	}
	
	public static Date getDate(long time) {
		return time == 0 ? null : new Date(time);
	}
	
	public static String putDateString(Date date) {
		return Long.toString(date == null ? 0 : date.getTime());
	}
	
	public static Date getDate(String time) {
		long ltime = Long.parseLong(time);
		return ltime == 0 ? null : new Date(ltime);
	}
	
	public static void putheader(HttpURLConnection conn, String header, Date date) {
		conn.addRequestProperty(header, Long.toString(date.getTime()));
	}
	
	public static Date getHeader(HttpURLConnection conn, String header) {
		String value = conn.getHeaderField(header);
		return (value == null) ? null : new Date(Long.parseLong(value));
	}

	public static DateFormat getDefaultFormat() {
		return SimpleDateFormat.getDateInstance();
	}
	
	public static String format(Date date) {
		if (date == null) {
			date = now();
		}
		return getDefaultFormat().format(date);
	}
	
	public static DateFormat getDateTimeFormat() {
		return SimpleDateFormat.getDateTimeInstance();
	}
	
	public static String dateTimeFormat(Date date) {
		if (date == null) {
			date = now();
		}
		return getDateTimeFormat().format(date);
	}
	
	public final static String SHORT_DATE_FORMAT = "MM/yyyy";
	
	public static String shortFormat(Date date) {
		SimpleDateFormat df = new SimpleDateFormat(SHORT_DATE_FORMAT);
		if (date == null) {
			return df.format(now());
		} else {
			return df.format(date);
		}
	}
	
	public static Date now() {
		return new Date(System.currentTimeMillis());
	}
	
	public static Date then(long msecsInFuture) {
		return new Date(System.currentTimeMillis() + msecsInFuture);
	}
	
	public static boolean expired(Date when, long msecsDuration) {
		return when.getTime()+msecsDuration < System.currentTimeMillis();
	}
	
	public static String simple(Date date) {
		return java.text.DateFormat.getDateInstance(java.text.DateFormat.SHORT, Locale.getDefault()).format(date);
	}
	
	public static Date readDate(XMLGregorianCalendar xcal) {
		return xcal.toGregorianCalendar().getTime();
	}
	
	public static XMLGregorianCalendar writeDate(Date date) {
		try {
			GregorianCalendar cal = new GregorianCalendar();
			cal.setTime(date);
			return DatatypeFactory.newInstance().newXMLGregorianCalendar(cal);
		} catch (DatatypeConfigurationException e) {
			throw ExceptionWrapper.wrap(IllegalStateException.class, e);
		}
	}
	
}
