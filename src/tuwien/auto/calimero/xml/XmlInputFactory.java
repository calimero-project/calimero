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

package tuwien.auto.calimero.xml;

import static java.lang.System.Logger.Level.TRACE;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.lang.System.Logger;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import tuwien.auto.calimero.log.LogService;

/**
 * Creates XML stream readers for working with XML resources. The factory tries to obtain a platform
 * reader implementation; if that fails, it might fall back on an internal minimal stream reader
 * implementation.
 *
 * @author B. Malinowsky
 */
public final class XmlInputFactory // extends XMLInputFactory
{
	private static final Logger l = LogService.getLogger("calimero.xml");

	private final Map<String, Object> config = new HashMap<>();
	private static final String RESOLVER = "javax.xml.stream.resolver";

	private XmlInputFactory() {}

	/**
	 * Returns a new instance of the XML factory.
	 *
	 * @return XmlInputFactory object
	 */
	public static XmlInputFactory newInstance()
	{
		return new XmlInputFactory();
	}

	/**
	 * Creates a {@link XmlReader} to read the XML resource located by the specified identifier.
	 * <p>
	 * On closing the created XML reader, the {@link Reader} set as input for the XML reader will
	 * get closed as well.
	 *
	 * @param baseUri location identifier of the XML resource
	 * @return XML reader
	 * @throws KNXMLException if creation of the reader failed or XML resource can't be resolved
	 */
	public XmlReader createXMLReader(final String baseUri) throws KNXMLException
	{
		final XmlResolver res = new XmlResolver();
		final InputStream is = (InputStream) res.resolveEntity(null, null, baseUri, null);
		return create(res, is);
	}

	private static XmlReader create(final XmlResolver resolver, final InputStream is)
	{
		try {
			final XmlStreamReaderProxy r = XmlStreamReaderProxy.createXmlReader(is, is);
			l.log(TRACE, "using StaX XMLStreamReader {0}", r.r.getClass().getName());
			return r;
		}
		catch (Exception | Error e) {
			l.log(TRACE, "no StaX implementation found ({0}), using internal XMLStreamReader", e.toString());
			// we fall back on our own minimal implementation
		}
		return new DefaultXmlReader(resolver.getInputReader(is), true);
	}

	public XmlReader createXMLStreamReader(final Reader reader)
	{
		try {
			final XmlStreamReaderProxy r = XmlStreamReaderProxy.createXmlReader(reader);
			l.log(TRACE, "using StaX XMLStreamReader {0}", r.r.getClass().getName());
			return r;
		}
		catch (Exception | Error e) {
			l.log(TRACE, "no StaX implementation found ({0}), using internal XMLStreamReader", e.toString());
			// we fall back on our own minimal implementation
		}
		return new DefaultXmlReader(reader, false);
	}

	public XmlReader createXMLStreamReader(final InputStream stream)
	{
		return createXMLStreamReader(new InputStreamReader(stream, Charset.forName("UTF-8")));
	}

	public XmlReader createXMLStreamReader(final InputStream stream, final String encoding)
	{
		try {
			return createXMLStreamReader(new InputStreamReader(stream, encoding));
		}
		catch (final UnsupportedEncodingException e) {
			throw new KNXMLException("XML stream reader with encoding " + encoding, e);
		}
	}

	public XmlReader createXMLStreamReader(final String systemId, final InputStream stream)
	{
		return createXMLStreamReader(stream);
	}

	public XmlReader createXMLStreamReader(final String systemId, final Reader reader)
	{
		return createXMLStreamReader(reader);
	}

	public XmlResolver getXMLResolver()
	{
		return (XmlResolver) config.get(RESOLVER);
	}

	public void setXMLResolver(final XmlResolver resolver)
	{
		config.put(RESOLVER, resolver);
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
