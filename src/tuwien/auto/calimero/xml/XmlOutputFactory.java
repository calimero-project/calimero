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

package tuwien.auto.calimero.xml;

import static java.lang.System.Logger.Level.TRACE;

import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.lang.System.Logger;
import java.util.HashMap;
import java.util.Map;

import tuwien.auto.calimero.log.LogService;

/**
 * Creates XML stream writers for working with XML resources. The factory tries to obtain a platform
 * writer implementation; if that fails, it might fall back on an internal minimal stream writer
 * implementation.
 *
 * @author B. Malinowsky
 */
public class XmlOutputFactory // extends XMLOutputFactory
{
	private static final Logger l = LogService.getLogger("calimero.xml");

	private final Map<String, Object> config = new HashMap<>();

	public static XmlOutputFactory newInstance()
	{
		return new XmlOutputFactory();
	}

	/**
	 * Creates a {@link XmlWriter} to write into the XML resource located by the specified identifier.
	 *
	 * @param systemId location identifier of the XML resource
	 * @return XML writer
	 * @throws KNXMLException if creation of the writer failed or XML resource can't be resolved
	 */
	public XmlWriter createXMLWriter(final String systemId) throws KNXMLException
	{
		final XmlResolver res = new XmlResolver();
		final OutputStream os = res.resolveOutput(systemId);
		return create(os, true);
	}

	public XmlWriter createXMLStreamWriter(final Writer stream)
	{
		try {
			final XmlStreamWriterProxy w = XmlStreamWriterProxy.createXmlStreamWriter(stream);
			l.log(TRACE, "using StaX XMLStreamWriter {0}", w.w.getClass().getName());
			return w;
		}
		catch (Exception | Error e) {
			l.log(TRACE, "no StaX implementation found ({0}), using internal XMLStreamWriter", e.toString());
			// fall-through to minimal writer implementation
		}
		return new DefaultXmlWriter(stream, false);
	}

	public XmlWriter createXMLStreamWriter(final OutputStream stream)
	{
		return create(stream, false);
	}

	private static XmlWriter create(final OutputStream stream, final boolean closeStream)
	{
		try {
			final XmlStreamWriterProxy w = XmlStreamWriterProxy.createXmlStreamWriter(stream,
					closeStream ? stream : () -> {});
			l.log(TRACE, "using StaX XMLStreamWriter {0}", w.w.getClass().getName());
			return w;
		}
		catch (Exception | Error e) {
			l.log(TRACE, "no StaX implementation found ({0}), using internal XMLStreamWriter", e.toString());
			// fall-through to minimal writer implementation
		}
		try {
			return new DefaultXmlWriter(new OutputStreamWriter(stream, "UTF-8"), closeStream);
		}
		catch (final UnsupportedEncodingException e) {
			throw new KNXMLException("encoding UTF-8 unknown", e);
		}
	}

	public XmlWriter createXMLStreamWriter(final OutputStream stream, final String encoding)
	{
		try {
			return createXMLStreamWriter(new OutputStreamWriter(stream, encoding));
		}
		catch (final UnsupportedEncodingException e) {
			throw new KNXMLException("encoding", e);
		}
	}

	public void setProperty(final String name, final Object value) throws IllegalArgumentException
	{
		config.put(name, value);
	}

	public Object getProperty(final String name) throws IllegalArgumentException
	{
		return config.get(name);
	}

	public boolean isPropertySupported(final String name)
	{
		return config.containsKey(name) && config.get(name).equals(Boolean.TRUE);
	}
}
