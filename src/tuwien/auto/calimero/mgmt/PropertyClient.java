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

package tuwien.auto.calimero.mgmt;

import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.WARNING;

import java.lang.System.Logger;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KNXRemoteException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.Settings;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.dptxlator.DPTXlator2ByteUnsigned;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.dptxlator.TranslatorTypes;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.xml.KNXMLException;
import tuwien.auto.calimero.xml.XmlInputFactory;
import tuwien.auto.calimero.xml.XmlOutputFactory;
import tuwien.auto.calimero.xml.XmlReader;
import tuwien.auto.calimero.xml.XmlWriter;

/**
 * A client to access properties in interface objects of a device.
 * <p>
 * This can be done in different ways, to specify the kind of access a property adapter is
 * supplied on creation of the property client. The implementation of the
 * {@link PropertyAdapter} interface methods don't need to be synchronized for use by this
 * property client.
 * <p>
 * Properties can be retrieved or set in the device, property descriptions can be read and
 * scans of properties can be done.<br>
 * If desired, the property data type of a property element is used to return an
 * appropriate DPT translator or the ready formatted string representation.<br>
 * The DPT translators used are requested from {@link PropertyTypes} by default, or, if
 * property definitions were loaded, there will be a lookup in these data at first (i.e.
 * loaded property definitions take priority over the default PDT to DPT mapping).
 * <p>
 * It is possible to load property definitions with information about KNX properties from
 * a resource to be used by the property client for lookup requests and property type
 * translation. Also, definitions can be saved to a resource. A global resource handler
 * takes care of working with the resources where those definitions are stored. Loaded
 * definitions can added to a property client for subsequent lookup.<br>
 * Nevertheless, adding any definitions is not required for a client to work properly,
 * i.e., this functionality is optional.
 * <p>
 * By default, the resource handler uses a xml property file structure.<br>
 * XML file layout: <br>
 * &lt;propertyDefinitions&gt;<br>
 * &lt;object type=(object-type:number | "global")&gt;<br>
 * &lt;property pid=PID:number pidName=PID-name:string name=friendly-name:string
 * pdt=PDT:number [dpt=DPT-ID:string] rw=("R"|"W"|"R/W"|"R(/W"):string
 * writeEnabled=("0"|"1"|"0/1"):string&gt;<br>
 * &lt;usage&gt;<br>
 * usage description and additional information<br>
 * &lt;/usage&gt;<br>
 * &lt;/property&gt;<br>
 * ...next property<br>
 * &lt;/object&gt;<br>
 * ...next object<br>
 * &lt;/propertyDefinitions&gt;<br>
 * <br>
 * Attribute values of type number might be written in hexadecimal form by prepending
 * "0x". The optional attribute "dpt" is to specify a DPT to use for the property, it will
 * be used in preference before the default DPT assigned to the PDT.<br>
 * The attribute "pdt" might have a value of "&lt;tbd&gt;", standing for "to be defined",
 * in this case the PDT value used by the property client is -1.
 * <p>
 * Reduced Property Interfaces:<br>
 * When working with reduced property interfaces, the user has to be aware of the
 * limitations and act accordingly.
 * <p>
 * Some KNX devices only support a 5 Bit field for storing the Property Data Type (PDT),
 * i.e., they only use a PDT identifier up to value 0x1F. When accessing property
 * descriptions in the interface object (for example, using
 * {@link PropertyClient#getDescription(int, int)}), not all existing PDTs can be
 * transmitted. Consequently, for properties that are formatted according any of the
 * higher PDTs, "alternative PDTs" get used. Following implementations are known to
 * support only a 5 Bit PDT in the description:
 * <ul>
 * <li>mask 0x0020</li>
 * <li>mask 0x0021</li>
 * <li>mask 0x0701</li>
 * </ul>
 * In general, it is not possible for the property client to deduce the actual type to use
 * for encoding/decoding values from such an "alternative PDT". For these cases, the
 * property client has to rely on property definitions supplied by the user through
 * {@link PropertyClient#addDefinitions(Collection)}.
 * <p>
 * A note on property descriptions:<br>
 * With a local device management adapter, not all information is supported when reading a
 * description, or is not supported by the protocol at all. In particular, no access
 * levels for read/write (i.e., access is always done with maximum rights) and no property
 * data type (PDT) are available. Also, the maximum number of elements allowed in the
 * property is not available (only the current number of elements).<br>
 * All methods for property access invoked after a close of the property client will throw
 * a {@link IllegalStateException}.
 *
 * @author B. Malinowsky
 * @see PropertyAdapter
 * @see PropertyTypes
 */
public class PropertyClient implements PropertyAccess, AutoCloseable
{
	/**
	 * Provides an interface to load property definitions from a resource, and store
	 * property definitions into a resource.
	 * <p>
	 * It is used by the property client when loading or saving of property definitions is
	 * requested.
	 * <p>
	 * To allow the property client handling a user defined property resource, create a
	 * new property resource implementing this interface and supply it to the load/save
	 * definition methods.<br>
	 * It is not necessary for subtypes implementing this interface to synchronize the
	 * methods for concurrent access. All library access to a resource handler instance
	 * will occur within the execution thread of the invoking method, or the library will
	 * ensure its own appropriate synchronization on the handler.
	 *
	 * @author B. Malinowsky
	 */
	public interface ResourceHandler
	{
		/**
		 * Loads the properties from the resource.
		 *
		 * @param resource the identifier of the resource used for loading the properties
		 * @return a collection containing the property definitions of type
		 *         {@link PropertyClient.Property}
		 * @throws KNXMLException on error reading from the resource
		 */
		Collection<Property> load(String resource) throws KNXMLException;

		/**
		 * Loads the properties using the XML reader.
		 *
		 * @param reader the XML reader parsing the resource containing the properties, the current
		 *        reader state has to be at, or exactly one event before, the property definition
		 *        start element
		 * @return a collection containing the property definitions of type
		 *         {@link PropertyClient.Property}
		 * @throws KNXMLException on error reading from the resource
		 */
		Collection<Property> load(XmlReader reader) throws KNXMLException;

		/**
		 * Saves the properties to the resource.
		 *
		 * @param resource the identifier of the resource used for saving the properties
		 * @param definitions the property definitions in a collection holding
		 *        {@link PropertyClient.Property}-type values
		 * @throws KNXMLException on error writing to the resource
		 */
		void save(String resource, Collection<Property> definitions) throws KNXMLException;

		/**
		 * Saves the properties to the resource.
		 *
		 * @param writer the XML writer writing the resource containing the properties
		 * @param definitions the property definitions in a collection holding
		 *        {@link PropertyClient.Property}-type values
		 * @throws KNXMLException on error writing to the resource
		 */
		void save(XmlWriter writer, Collection<Property> definitions) throws KNXMLException;
	}

	/**
	 * Key value in the map returned by {@link PropertyClient#getDefinitions()}.
	 * <p>
	 * A key consists of the interface object type and the property identifier of the
	 * associated property. If the property is defined globally, the global object type
	 * {@link PropertyClient.PropertyKey#GLOBAL_OBJTYPE} is used.
	 *
	 * @author B. Malinowsky
	 */
	public static final class PropertyKey implements Comparable<PropertyKey>
	{
		/** Identifier for a property defined with global object type. */
		public static final int GLOBAL_OBJTYPE = -1;

		private final int ot;
		private final int id;

		/**
		 * Creates a new key for a global defined property.
		 *
		 * @param pid property identifier
		 */
		public PropertyKey(final int pid)
		{
			ot = GLOBAL_OBJTYPE;
			id = pid;
		}

		/**
		 * Creates a new key for a property.
		 *
		 * @param objType object type of the property
		 * @param pid property identifier
		 */
		public PropertyKey(final int objType, final int pid)
		{
			ot = objType;
			id = pid;
		}

		/**
		 * Returns the property identifier part of this key.
		 *
		 * @return the PID as unsigned number
		 */
		public int getPID()
		{
			return id;
		}

		/**
		 * Returns whether the property is defined with global object type.
		 *
		 * @return {@code true} if property has global object type,
		 *         {@code false} if property has a specific object type
		 */
		public boolean isGlobal()
		{
			return ot == GLOBAL_OBJTYPE;
		}

		@Override
		public int hashCode()
		{
			return ot << 16 | id;
		}

		@Override
		public boolean equals(final Object obj)
		{
			if (obj instanceof PropertyKey) {
				final PropertyKey key = (PropertyKey) obj;
				return ot == key.ot && id == key.id;
			}
			return false;
		}

		@Override
		public int compareTo(final PropertyKey o)
		{
			final int rhs = o.hashCode();
			return hashCode() < rhs ? -1 : hashCode() > rhs ? 1 : 0;
		}

		@Override
		public String toString() {
			return getObjectTypeName(ot) + " PID " + id;
		}
	}

	/**
	 * Stores property definition information of one property, used for type translation
	 * and property lookup by a property client.
	 *
	 * @author B. Malinowsky
	 */
	public static class Property
	{
		final int id;
		final String name;
		final String propName;
		final String description;
		final int objType;
		final int pdt;
		final String dpt;
		final int read;
		final int write;
		final int accessPolicy;

		/**
		 * Creates a new property object of the supplied information.
		 *
		 * @param pid property identifier
		 * @param pidName name of the property ID
		 * @param propertyName property name, a friendly readable name for the property
		 * @param objectType object type the property belongs to
		 * @param pdt property data type
		 * @param dpt datapoint type, use {@code null} if no DPT specified or to
		 *        indicate default DPT usage
		 */
		public Property(final int pid, final String pidName, final String propertyName,
			final int objectType, final int pdt, final String dpt)
		{
			this(pid, pidName, propertyName, "n/a", objectType, pdt, dpt, 0, 0, 0);
		}

		Property(final int pid, final String pidName, final String propertyName, final String description,
				final int objectType, final int pdt, final String dpt, final int readLevel, final int writeLevel,
				final int accessPolicy) {
			id = pid;
			name = pidName;
			propName = propertyName;
			this.description = description;
			objType = objectType;
			this.pdt = pdt;
			this.dpt = dpt;
			read = readLevel;
			write = writeLevel;
			this.accessPolicy = accessPolicy;
		}

		/**
		 * Returns the property identifier.
		 * <p>
		 *
		 * @return the PID
		 */
		public final int getPID()
		{
			return id;
		}

		/**
		 * Returns the PID name as string representation.
		 *
		 * @return the PID name as string
		 */
		public final String getPIDName()
		{
			return name;
		}

		/**
		 * Returns the interface object type the property belongs to.
		 * <p>
		 *
		 * @return the interface object type
		 */
		public final int getObjectType()
		{
			return objType;
		}

		/**
		 * Returns the property data type used for the property elements.
		 * <p>
		 *
		 * @return the PDT
		 */
		public final int getPDT()
		{
			return pdt;
		}

		/**
		 * @return the datapoint type ID used for the property elements, or an empty optional if no DPT was set
		 */
		public final Optional<String> dpt() { return Optional.ofNullable(dpt); }

		/**
		 * Returns the property friendly name, a more readable name of the property.
		 *
		 * @return the property name
		 */
		public final String getName()
		{
			return propName;
		}

		public final String description() { return description; }

		/**
		 * @return {@code true} if property is read-only, {@code false} if property is write-enabled
		 */
		public final boolean readOnly()
		{
			return write == -1;
		}

		/**
		 * @return required access level for property write access to write-enabled property, {@code level ≥ 0};
		 *         level is undefined for read-only property
		 */
		public final int writeLevel() {
			return write;
		}

		/**
		 * @return required access level for property read access, level &ge; 0
		 */
		public final int readLevel() {
			return read;
		}

		/**
		 * @return access policy for security modes off/on, or 0 if no policy is set
		 */
		public final int accessPolicy() { return accessPolicy; }

		@Override
		public String toString() {
			return name + " (" + id + ") '" + propName + "'" + (objType == -1 ? "" : " OT " + objType) + " PDT " + pdt
					+ dpt().map(s -> " DPT " + s).orElse("") + " r/w " + read + "/" + (readOnly() ? "-" : write)
					+ accessPolicyString();
		}

		private String accessPolicyString() {
			if (accessPolicy == 0)
				return "";
			return String.format(" %03x/%03x", accessPolicy >> 10, accessPolicy & 0x3ff);
		}
	}

	// mapping of object type numbers to the associated object type names
	// the offset of a name in the array corresponds to the object type number
	private static final String[] OBJECT_TYPE_NAMES = { "Device Object",
		"Addresstable Object", "Associationtable Object", "Applicationprogram Object",
		"Applicationprogram 2 Object", "KNX-Object Associationtable Object", "Router Object",
		"LTE Address Filter Table Object", "cEMI Server Object",
		"Group Object Table Object", "Polling Master", "KNXnet/IP Parameter Object",
		"Application Controller", "File Server Object", "", "", "", "Security Object", "", "RF Medium Object" };


	private final Map<PropertyKey, Property> properties = Collections.synchronizedMap(new HashMap<>());

	private final PropertyAdapter pa;
	// helper flag to determine local DM mode, mainly for detecting absence of PDT
	// detection is currently done by querying PropertyAdapter.getName()
	private final boolean local;
	private final Logger logger;

	// maps object index to object type
	private final List<Pair> objectTypes = new ArrayList<>();
	private final DPTXlator2ByteUnsigned tObjType;

	/**
	 * Creates a new property client using the specified adapter for accessing device
	 * properties.
	 * <p>
	 * The property client obtains ownership of the adapter.<br>
	 * The log service used by this property client is named "PC " + adapter.getName().
	 *
	 * @param adapter property adapter object
	 * @throws KNXFormatException on missing DPT for translating interface object types (
	 *         DPTXlator2ByteUnsigned.DPT_PROP_DATATYPE)
	 */
	public PropertyClient(final PropertyAdapter adapter) throws KNXFormatException
	{
		pa = adapter;
		local = adapter instanceof LocalDeviceManagement
				|| pa.getName().toLowerCase().startsWith("local");
		try {
			tObjType = new DPTXlator2ByteUnsigned(DPTXlator2ByteUnsigned.DPT_PROP_DATATYPE);
		}
		catch (final KNXFormatException e) {
			pa.close();
			throw e;
		}
		logger = LogService.getLogger("calimero.mgmt.PC " + pa.getName());
	}

	/**
	 * Returns the object type name of the requested object type.
	 *
	 * @param objType object type to get name for
	 * @return object type name as string
	 */
	public static String getObjectTypeName(final int objType)
	{
		if (objType < OBJECT_TYPE_NAMES.length)
			return OBJECT_TYPE_NAMES[objType];
		return "";
	}

	/**
	 * Adds the property definitions contained in the collection argument to the property
	 * definitions of the property client.
	 * <p>
	 * Any definitions already existing in the client are not removed before adding new
	 * ones. To remove definitions, use {@link #getDefinitions()} and remove entries
	 * manually.<br>
	 * An added property definition will replace an existing definition with its property
	 * key being equal to the one of the added definition.
	 *
	 * @param definitions collection of property definitions, containing entries of type
	 *        {@link Property}
	 */
	public void addDefinitions(final Collection<Property> definitions)
	{
		for (final Iterator<Property> i = definitions.iterator(); i.hasNext();) {
			final Property p = i.next();
			properties.put(new PropertyKey(p.objType, p.id), p);
		}
	}

	/**
	 * Returns the property definitions used by property clients.
	 * <p>
	 * The returned map is synchronized and references the one used by the property
	 * client. Property definitions might be added or removed as required. Modifications
	 * will influence subsequent lookup behavior of the property client.<br>
	 *
	 * @return property map
	 */
	public Map<PropertyKey, Property> getDefinitions()
	{
		return properties;
	}

	@Override
	public void setProperty(final int objIndex, final int pid, final int position,
		final String value) throws KNXException, InterruptedException
	{
		final DPTXlator t = createTranslator(objIndex, pid);
		t.setValue(value);
		setProperty(objIndex, pid, position, t.getItems(), t.getData());
	}

	/**
	 * Gets the first property element using the associated property data type of the
	 * requested property.
	 *
	 * @param objIndex interface object index in the device
	 * @param pid property identifier
	 * @return property element value represented as string
	 * @throws KNXException on adapter errors while querying the property element or data
	 *         type translation problems
	 * @throws InterruptedException on thread interrupt
	 */
	public String getProperty(final int objIndex, final int pid) throws KNXException,
		InterruptedException
	{
		return getPropertyTranslated(objIndex, pid, 1, 1).getValue();
	}

	@Override
	public void setProperty(final int objIndex, final int pid, final int start,
		final int elements, final byte... data) throws KNXException, InterruptedException
	{
		pa.setProperty(objIndex, pid, start, elements, data);
	}

	@Override
	public byte[] getProperty(final int objIndex, final int pid, final int start,
		final int elements) throws KNXException, InterruptedException
	{
		return pa.getProperty(objIndex, pid, start, elements);
	}

	@Override
	public DPTXlator getPropertyTranslated(final int objIndex, final int pid,
		final int start, final int elements) throws KNXException, InterruptedException
	{
		final DPTXlator t = createTranslator(objIndex, pid);
		t.setData(getProperty(objIndex, pid, start, elements));
		return t;
	}

	@Override
	public Description getDescription(final int objIndex, final int pid) throws KNXException, InterruptedException
	{
		if (pid == 0)
			throw new KNXIllegalArgumentException("pid has to be > 0");
		return createDesc(objIndex, pa.getDescription(objIndex, pid, 0));
	}

	/**
	 * Gets the property description based on the property index.
	 *
	 * @param objIndex interface object index in the device
	 * @param propIndex property index in the object
	 * @return a property description object
	 * @throws KNXException on adapter errors while querying the description
	 */
	@Override
	public Description getDescriptionByIndex(final int objIndex, final int propIndex)
		throws KNXException, InterruptedException
	{
		return createDesc(objIndex, pa.getDescription(objIndex, 0, propIndex));
	}

	/**
	 * Does a property description scan of the properties in all interface objects.
	 *
	 * @param allProperties {@code true} to scan all property descriptions in the interface
	 *        objects, {@code false} to only scan the object type descriptions, i.e.,
	 *        {@link PropertyAccess.PID#OBJECT_TYPE}
	 * @param consumer invoked on every property read during the scan, taking a property
	 *        {@link Description} argument
	 * @throws KNXException on adapter errors while querying the descriptions
	 * @throws InterruptedException on thread interrupt
	 */
	public void scanProperties(final boolean allProperties, final Consumer<Description> consumer)
		throws KNXException, InterruptedException
	{
		for (int index = 0; scan(index, allProperties, consumer) > 0; ++index);
	}

	/**
	 * Does a property description scan of the properties of one interface object.
	 *
	 * @param objIndex interface object index in the device
	 * @param allProperties {@code true} to scan all property descriptions in that interface
	 *        object, {@code false} to only scan the object type description of the interface
	 *        object specified by {@code objIndex}, i.e.,
	 *        {@link PropertyAccess.PID#OBJECT_TYPE}
	 * @param consumer invoked on every property read during the scan, taking a property
	 *        {@link Description} argument
	 * @throws KNXException on adapter errors while querying the descriptions
	 * @throws InterruptedException on thread interrupt
	 */
	public void scanProperties(final int objIndex, final boolean allProperties,
		final Consumer<Description> consumer) throws KNXException, InterruptedException
	{
		scan(objIndex, allProperties, consumer);
	}

	/**
	 * Returns whether the adapter used for property access is opened.
	 * <p>
	 *
	 * @return {@code true} on open adapter, {@code false} on closed adapter
	 */
	public final boolean isOpen()
	{
		return pa.isOpen();
	}

	/**
	 * Closes the property client and the used adapter.
	 */
	@Override
	public void close()
	{
		if (pa.isOpen()) {
			pa.close();
			logger.log(INFO, "closed property client");
		}
	}

	private int scan(final int objIndex, final boolean allProperties,
		final Consumer<Description> consumer) throws KNXException, InterruptedException
	{
		int i = 0;
		try {
			if (!allProperties) {
				// specifically ask for pid 1 -> description of object type
				consumer.accept(createDesc(objIndex, pa.getDescription(objIndex, 1, 0)));
				return 1;
			}
			// property with index 0 is description of object type
			// rest are ordinary properties of the object
			for (;; ++i) {
				try {
					consumer.accept(createDesc(objIndex, pa.getDescription(objIndex, 0, i)));
				}
				catch (final KNXTimeoutException e) {
					// retry once on timeout so we don't immediately fail the whole scan
					consumer.accept(createDesc(objIndex, pa.getDescription(objIndex, 0, i)));
				}
			}
		}
		catch (final KNXException e) {
			if (!KNXRemoteException.class.equals(e.getClass()) && !KNXTimeoutException.class.equals(e.getClass())) {
				logger.log(ERROR, "scan properties failed", e);
				throw e;
			}
		}
		return i;
	}

	private Description createDesc(final int oi, final byte[] desc) throws KNXException, InterruptedException
	{
		final int pid = desc[1] & 0xff;
		byte[] data = new byte[4];
		try {
			data = pa.getProperty(oi, pid, 0, 1);
		}
		catch (final KNXRemoteException e) {
			logger.log(WARNING, "failed to get current number of elements for OI {0} PID {1}: {2}", oi, pid, e.getMessage());
		}
		final Description d = new Description(getObjectType(oi, true), Description.parseCurrentElements(data), desc);
		// workaround for PDT on local DM
		if (local)
			d.setPDT(-1);
		return d;
	}

	private int getObjectType(final int objIndex, final boolean queryObject) throws KNXException, InterruptedException
	{
		for (final Iterator<Pair> i = objectTypes.iterator(); i.hasNext();) {
			final Pair p = i.next();
			if (p.oindex == objIndex)
				return p.otype;
		}
		if (queryObject)
			return queryObjectType(objIndex);
		throw new KNXException("couldn't deduce object type");
	}

	private int queryObjectType(final int objIndex) throws KNXException, InterruptedException
	{
		if (pa instanceof LocalDeviceManagement) {
			final LocalDeviceManagement<?> ldm = (LocalDeviceManagement<?>) pa;
			final int ot = ldm.getObjectType(objIndex);
			objectTypes.add(new Pair(objIndex, ot));
			return ot;
		}
		final byte[] objectType = pa.getProperty(objIndex, PID.OBJECT_TYPE, 1, 1);
		tObjType.setData(objectType);
		objectTypes.add(new Pair(objIndex, tObjType.getValueUnsigned()));
		return tObjType.getValueUnsigned();
	}

	private DPTXlator createTranslator(final int objIndex, final int pid) throws KNXException, InterruptedException
	{
		final int ot = getObjectType(objIndex, true);
		int pdt = -1;
		Property p = properties.get(new PropertyKey(ot, pid));
		// if no property found, lookup global pid
		if (p == null && pid <= 50)
			p = properties.get(new PropertyKey(pid));
		if (p != null) {
			if (p.dpt != null)
				try {
					final DPTXlator t = TranslatorTypes.createTranslator(0, p.dpt);
					t.setAppendUnit(false);
					return t;
				}
				catch (final KNXException e) {
					logger.log(WARNING, "fallback to default translator for PID " + pid
							+ ", no translator for DPT " + p.dpt, e);
				}
			pdt = p.pdt;
		}
		// if we didn't get pdt from definitions, query property description,
		// in local dev.mgmt, no pdt description is available
		if (pdt == -1 && !local)
			pdt = pa.getDescription(objIndex, pid, 0)[3] & 0x3f;
		if (PropertyTypes.hasTranslator(pdt)) {
			final DPTXlator t = PropertyTypes.createTranslator(pdt);
			t.setAppendUnit(false);
			return t;
		}
		throw new KNXException("no translator available for PID " + pid + " in " + getObjectTypeName(ot) + " (OT " + ot
				+ "), PDT " + pdt + " ");
	}

	public static class XmlPropertyDefinitions implements ResourceHandler
	{
		private static final String PROPDEFS_TAG = "propertyDefinitions";
		private static final String OBJECT_TAG = "object";
		private static final String OBJECTTYPE_ATTR = "type";
		private static final String PROPERTY_TAG = "property";
		private static final String PID_ATTR = "pid";
		private static final String PIDNAME_ATTR = "pidName";
		private static final String NAME_ATTR = "name";
		private static final String PDT_ATTR = "pdt";
		private static final String DPT_ATTR = "dpt";
		private static final String RW_ATTR = "rw";
		private static final String WRITE_ATTR = "writeEnabled";
		private static final String USAGE_TAG = "usage";

		@Override
		public Collection<Property> load(final String resource) throws KNXMLException
		{
			try (XmlReader r = XmlInputFactory.newInstance().createXMLReader(resource)) {
				return load(r);
			}
		}

		@Override
		public Collection<Property> load(final XmlReader reader) throws KNXMLException
		{
			final List<Property> list = new ArrayList<>();
			int objType = -1;
			try {
				if (reader.nextTag() != XmlReader.START_ELEMENT || !reader.getLocalName().equals(PROPDEFS_TAG))
					throw new KNXMLException("no property defintions");
				while (reader.hasNext()) {
					final int event = reader.next();
					if (event == XmlReader.START_ELEMENT) {
						if (reader.getLocalName().equals(OBJECT_TAG)) {
							// on no type attribute, toInt() throws, that's ok
							final String type = reader.getAttributeValue("", OBJECTTYPE_ATTR);
							objType = "global".equals(type) ? -1 : toInt(type);
						}
						else if (reader.getLocalName().equals(PROPERTY_TAG)) {
							final int pid = toInt(reader.getAttributeValue("", PID_ATTR));
							final String pidName = reader.getAttributeValue("", PIDNAME_ATTR);
							final String friendly = reader.getAttributeValue("", NAME_ATTR);
							final int pdt = toInt(reader.getAttributeValue("", PDT_ATTR));
							final String dpt = reader.getAttributeValue("", DPT_ATTR);

							final int[] rw = parseRW(reader.getAttributeValue("", RW_ATTR));
							final boolean write = parseWriteEnabled(reader.getAttributeValue("", WRITE_ATTR));
							final int accessPolicy = parseAccessPolicy(reader.getAttributeValue("", "accessPolicy"));

							String description = "";
							if (reader.nextTag() == XmlReader.START_ELEMENT
									&& reader.getLocalName().equals(USAGE_TAG))
								description = reader.getElementText();

							list.add(new Property(pid, pidName, friendly, description, objType, pdt, dpt, rw[0],
									write ? rw[1] : -1, accessPolicy));
						}
					}
					else if (event == XmlReader.END_ELEMENT && reader.getLocalName().equals(PROPDEFS_TAG))
						break;
				}
				return list;
			}
			catch (final KNXFormatException e) {
				throw new KNXMLException("loading property definitions, " + e.getMessage());
			}
		}

		@Override
		public void save(final String resource, final Collection<Property> definitions)
		{
			try (XmlWriter w = XmlOutputFactory.newInstance().createXMLWriter(resource)) {
				w.writeStartDocument("UTF-8", "1.0");
				save(w, definitions);
				w.writeEndDocument();
			}
		}

		@Override
		public void save(final XmlWriter writer, final Collection<Property> definitions)
		{
			writer.writeComment("Calimero v" + Settings.getLibraryVersion() + " KNX property definitions, saved on "
					+ ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME));
			writer.writeStartElement(PROPDEFS_TAG);
			final int noType = -2;
			int objType = noType;
			for (final Iterator<Property> i = definitions.iterator(); i.hasNext();) {
				final Property p = i.next();
				if (p.objType != objType) {
					if (objType != noType)
						writer.writeEndElement();
					objType = p.objType;
					writer.writeStartElement(OBJECT_TAG);
					writer.writeAttribute(OBJECTTYPE_ATTR, objType == -1 ? "global"
							: Integer.toString(objType));
				}
				// property attributes
				writer.writeStartElement(PROPERTY_TAG);
				writer.writeAttribute(PID_ATTR, Integer.toString(p.id));
				writer.writeAttribute(PIDNAME_ATTR, p.name);
				writer.writeAttribute(NAME_ATTR, p.propName);
				writer.writeAttribute(PDT_ATTR, p.pdt == -1 ? "<tbd>" : Integer.toString(p.pdt));
				if (p.dpt != null && p.dpt.length() > 0)
					writer.writeAttribute(DPT_ATTR, p.dpt);
				writer.writeAttribute(RW_ATTR, String.format("%d/%d", p.read, p.write));
				writer.writeAttribute(WRITE_ATTR, p.readOnly() ? "0" : "1");
				// write property
				writer.writeStartElement(USAGE_TAG);
				writer.writeEndElement();
				writer.writeEndElement();
			}
			writer.writeEndElement();
		}

		private static int[] parseRW(final String rw)
		{
			final String s = rw.toLowerCase();
			int read = 0;
			int write = 0;
			boolean slash = false;
			for (int i = 0; i < s.length(); i++) {
				final char c = s.charAt(i);
				if (c == '/')
					slash = true;
				else if (c >= '0' && c <= '9')
					if (slash)
						write = write * 10 + c - '0';
					else
						read = read * 10 + c - '0';
				else if (c == 'r')
					read = 3;
				else if (c == 'w')
					write = 3;
			}
			return new int[] { read, write };
		}

		private static boolean parseWriteEnabled(final String attribute)
		{
			final String s = attribute.toLowerCase();
			if ("0".equals(s) || "false".equals(s))
				return false;
			if ("1".equals(s) || "true".equals(s))
				return true;
			if ("w".equals(s))
				return true;
			return false;
		}

		private static int parseAccessPolicy(final String attribute) throws KNXFormatException {
			if (attribute == null || attribute.isEmpty())
				return 0;
			final int slash = attribute.indexOf('/');
			final int off = Integer.parseInt(attribute.substring(0, slash), 16);
			final int on = Integer.parseInt(attribute.substring(slash + 1), 16);
			if (off > 0x3ff || on > 0x3ff)
				throw new KNXFormatException("invalid access policy", attribute);
			return (off << 10) | on;
		}

		private static int toInt(final String s) throws KNXFormatException
		{
			try {
				if (s != null) {
					if (s.equals("<tbd>") || s.equals("-"))
						return -1;
					return s.length() == 0 ? 0 : Integer.decode(s).intValue();
				}
			}
			catch (final NumberFormatException e) {}
			throw new KNXFormatException("cannot convert to number", s);
		}
	}

	private static final class Pair
	{
		final int oindex;
		final int otype;

		Pair(final int objIndex, final int objType)
		{
			oindex = objIndex;
			otype = objType;
		}
	}
}
