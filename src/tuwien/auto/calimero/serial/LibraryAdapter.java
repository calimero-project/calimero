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

package tuwien.auto.calimero.serial;

import static java.lang.System.Logger.Level.DEBUG;

import java.io.IOException;
import java.lang.System.Logger;
import java.util.List;
import java.util.Locale;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.ServiceLoader.Provider;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.serial.spi.SerialCom;
import tuwien.auto.calimero.serial.spi.SerialCom.FlowControl;
import tuwien.auto.calimero.serial.spi.SerialCom.Parity;
import tuwien.auto.calimero.serial.spi.SerialCom.StopBits;

/**
 * Adapter to access a serial communication port using a {@link SerialCom} service provider.
 *
 * @author B. Malinowsky
 */
public final class LibraryAdapter
{
	private LibraryAdapter() {}

	private static class SerialComLoader {
		private static final ServiceLoader<SerialCom> loader = ServiceLoader.load(SerialCom.class);

		static Stream<Provider<SerialCom>> providers(final boolean refresh) {
			if (refresh)
				loader.reload();
			return loader.stream();
		}
	}

	private static final List<String> defaultPortPrefixes = System.getProperty("os.name").toLowerCase(Locale.ENGLISH)
			.indexOf("windows") > -1
					? List.of("\\\\.\\COM")
					: List.of("/dev/ttyS", "/dev/ttyACM", "/dev/ttyUSB", "/dev/ttyAMA");

	static List<String> defaultPortPrefixes() { return defaultPortPrefixes; }

	/** @return all available serial communication port identifiers. */
	public static List<String> getPortIdentifiers() {
		for (final var provider : SerialComLoader.providers(false).collect(Collectors.toList())) {
			try {
				final var inst = provider.get();
				return inst.portIdentifiers();
			}
			catch (final ServiceConfigurationError e) {
				final var ex = e.getCause() != null ? e.getCause() : e;
				LogService.getLogger("calimero.serial").log(DEBUG, "skip service provider {0}", provider.type().getName(), ex);
			}
		}
		return List.of();
	}

	/**
	 * Factory method to open a serial connection using one of the available library adapters.
	 *
	 * @param logger logger
	 * @param portId serial port identifier
	 * @param baudrate baudrate
	 * @param idleTimeout idle timeout in milliseconds
	 * @return adapter to access serial communication port, port resource is in open state
	 * @throws KNXException on failure to open or configure serial port, or no adapter available
	 */
	public static SerialCom open(final Logger logger, final String portId, final int baudrate,
		final int idleTimeout) throws KNXException
	{
		Throwable t = null;

		for (final var provider : SerialComLoader.providers(false).collect(Collectors.toList())) {
			try {
				return open(provider, logger, portId, baudrate, idleTimeout);
			}
			catch (final ServiceConfigurationError e) {
				final var ex = e.getCause() != null ? e.getCause() : e;
				logger.log(DEBUG, "skip service provider {0}: {1}", provider.type().getName(), ex.getMessage());
			}
			catch (final Throwable e) {
				t = e;
			}
		}

		if (t instanceof KNXException)
			throw (KNXException) t;
		if (t != null)
			throw new KNXException("failed to open serial port " + portId, t);
		throw new KNXException("no serial provider available to open " + portId);
	}

	private static SerialCom open(final Provider<SerialCom> provider, final Logger logger, final String portId,
			final int baudrate, final int idleTimeout) throws Throwable {

		final var inst = provider.get();
		logger.log(DEBUG, "open serial communication provider {0}", provider.type().getName());
		inst.open(portId);
		try {
			inst.setSerialPortParams(baudrate, 8, StopBits.One, Parity.Even);
			inst.setFlowControlMode(FlowControl.None);

			if (provider.type().equals(SerialComAdapter.class)) {
				final SerialComAdapter conn = (SerialComAdapter) inst;
				//final int idleTimeout = idleTimeout(conn.getBaudRate());
				conn.setTimeouts(new SerialComAdapter.Timeouts(idleTimeout, 0, 5, 0, 0));
			}
		}
		catch (IOException | RuntimeException e) {
			inst.close();
			throw e;
		}
		logger.log(DEBUG, "serial port setup: {0}", inst);
		return inst;
	}
}
