/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2015, 2022 B. Malinowsky

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

package tuwien.auto.calimero.link;

import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

import java.lang.System.Logger;

import tuwien.auto.calimero.CloseEvent;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.cemi.CEMI;
import tuwien.auto.calimero.cemi.CEMIBusMon;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.link.medium.RawFrame;
import tuwien.auto.calimero.link.medium.RawFrameFactory;
import tuwien.auto.calimero.log.LogService;

/**
 * Provides an abstract KNX network monitor implementation, independent of the actual communication
 * protocol and medium access. The monitor supports EMI1/EMI2/cEMI format. Subtypes extend the
 * abstract monitor by specifying the protocol, e.g., KNXnet/IP, or providing a specific
 * implementation of medium access, e.g., via a serial port driver. In most cases, it is sufficient
 * for a subtype to provide an implementation of {@link #onClose()}. For receiving and dispatching
 * frames from the specified protocol, a subtype uses the KNXListener {@link AbstractLink#notifier}
 * as connection listener.
 * <p>
 * In general, once a monitor has been closed, it is not available for further communication and
 * cannot be reopened.
 *
 * @author B. Malinowsky
 */
public abstract class AbstractMonitor<T extends AutoCloseable> implements KNXNetworkMonitor
{
	/** Implements KNXListener to listen to the monitor connection. */
	protected final MonitorNotifier notifier;
	protected final Logger logger;

	final T conn;

	volatile boolean wrappedByConnector;
	private volatile boolean closed;
	private KNXMediumSettings medium;
	private final String name;

	private static final class MonitorNotifier extends EventNotifier<LinkListener>
	{
		volatile boolean decode;
		private boolean extBusmon;

		MonitorNotifier(final AbstractMonitor<?> source, final Logger logger, final boolean extBusmon)
		{
			super(source, logger);
			this.extBusmon = extBusmon;
		}

		@Override
		public void frameReceived(final FrameEvent e)
		{
			try {
				final CEMI frame = e.getFrame();

				final CEMIBusMon mon;
				if (frame == null)
					mon = (CEMIBusMon) CEMIFactory.fromEmiBusmon(e.getFrameBytes());
				else if (frame instanceof CEMIBusMon)
					mon = (CEMIBusMon) frame;
				else {
					logger.log(WARNING, "received unsupported frame type with msg code 0x"
							+ Integer.toHexString(frame.getMessageCode()));
					return;
				}
				logger.log(TRACE, "{0}", mon);
				final AbstractMonitor<?> netmon = (AbstractMonitor<?>) source;
				MonitorFrameEvent mfe = new MonitorFrameEvent(netmon, mon);
				if (decode) {
					try {
						final RawFrame rf = RawFrameFactory.create(netmon.medium.getMedium(),
								mon.getPayload(), 0, extBusmon);
						mfe = new MonitorFrameEvent(netmon, mon, rf);
					}
					catch (final KNXFormatException ex) {
						logger.log(WARNING, "decoding raw frame", ex);
						mfe = new MonitorFrameEvent(netmon, mon, ex);
						// workaround for PL, BCU might not have switched to ext. busmonitor
						if (extBusmon) {
							extBusmon = false;
							logger.log(WARNING, "disable extended busmonitor mode, maybe this helps");
						}
					}
				}
				final var event = mfe;
				addEvent(l -> l.indication(event));
			}
			catch (KNXFormatException | RuntimeException ex) {
				logger.log(WARNING, "unspecified frame event - ignored", ex);
			}
		}

		@Override
		public void connectionClosed(final CloseEvent e)
		{
			final var monitor = (AbstractMonitor<?>) source;
			monitor.closed = true;
			logger.log(INFO, "monitor closed");
			if (monitor.wrappedByConnector) {
				getListeners().listeners().stream().filter(Connector.Link.class::isInstance)
						.forEach(l -> l.linkClosed(e));
				return;
			}
			super.connectionClosed(e);
		}
	}

	protected AbstractMonitor(final T conn, final String name, final KNXMediumSettings settings) {
		this.conn = conn;
		this.name = name;
		logger = LogService.getLogger("calimero.link." + getName());

		if (settings instanceof PLSettings)
			logger.log(INFO, "power-line medium, assuming BCU has extended busmonitor enabled");

		setKNXMedium(settings);
		notifier = new MonitorNotifier(this, logger, settings instanceof PLSettings);
		notifier.start();
	}

	@Override
	public final void setKNXMedium(final KNXMediumSettings settings)
	{
		if (settings == null)
			throw new KNXIllegalArgumentException("medium settings are mandatory");
		if (medium != null && !settings.getClass().isAssignableFrom(medium.getClass())
				&& !medium.getClass().isAssignableFrom(settings.getClass()))
			throw new KNXIllegalArgumentException("medium differs");
		medium = settings;
	}

	@Override
	public final KNXMediumSettings getKNXMedium()
	{
		return medium;
	}

	@Override
	public void addMonitorListener(final LinkListener l)
	{
		notifier.addListener(l);
	}

	@Override
	public void removeMonitorListener(final LinkListener l)
	{
		notifier.removeListener(l);
	}

	@Override
	public final void setDecodeRawFrames(final boolean decode)
	{
		notifier.decode = decode;
		logger.log(INFO, (decode ? "enable" : "disable") + " decoding of raw frames");
	}

	@Override
	public final String getName()
	{
		return name;
	}

	@Override
	public boolean isOpen()
	{
		return !closed;
	}

	@Override
	public final void close()
	{
		synchronized (this) {
			if (closed)
				return;
			closed = true;
		}
		try {
			leaveBusmonitor();
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		onClose();
		try {
			if (conn != null)
				conn.close();
		}
		catch (final Exception ignore) {}
		notifier.quit();
	}

	@Override
	public String toString()
	{
		return "monitor " + getName() + " " + medium.getMediumString() + " medium"
				+ (notifier.decode ? ", raw frame decoding" : "") + (closed ? " (closed)" : "");
	}

	/**
	 * Invoked on {@link #close()} to execute additional close sequences of the communication
	 * protocol, or releasing link-specific resources.
	 */
	protected void onClose()
	{}

	/**
	 * Invoked on {@link #close()} to allow the communication protocol to leave busmonitor mode.
	 *
	 * @throws InterruptedException on interrupted thread
	 */
	@SuppressWarnings("unused")
	protected void leaveBusmonitor() throws InterruptedException
	{}
}
