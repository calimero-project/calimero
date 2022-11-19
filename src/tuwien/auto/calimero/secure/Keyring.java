/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2019, 2022 B. Malinowsky

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

package tuwien.auto.calimero.secure;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static java.util.function.Predicate.isEqual;
import static java.util.function.Predicate.not;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.knxnetip.SecureConnection;
import tuwien.auto.calimero.log.LogService;
import tuwien.auto.calimero.secure.Keyring.Interface.Type;
import tuwien.auto.calimero.xml.KNXMLException;
import tuwien.auto.calimero.xml.XmlInputFactory;
import tuwien.auto.calimero.xml.XmlReader;

/**
 * Loads an ETS project keyring file. Methods parsing the keyring resource can throw {@link KNXMLException}; methods
 * decrypting keys or passwords can throw {@link KnxSecureException}.
 */
public final class Keyring {

	public static final class Interface {
		public enum Type {
			Backbone, Tunneling, Usb;

			// parse value from xsd Type enumeration
			static Type from(final String type) {
				switch (type) {
					case "Backbone": return Backbone;
					case "Tunneling": return Tunneling;
					case "USB": return Usb; // important: USB is specified upper-case
				}
				throw new KNXIllegalArgumentException("unknown interface type " + type);
			}
		}


		private final Keyring keyring;
		private final String type; // TODO candidate for subtyping via sealed interface
		private final IndividualAddress addr;
		private final int user;
		private final byte[] pwd;
		private final byte[] auth;
		private volatile Map<GroupAddress, Set<IndividualAddress>> groups = Map.of();

		Interface(final Keyring keyring, final String type, final IndividualAddress addr, final int user,
				final byte[] pwd, final byte[] auth) {
			this.keyring = keyring;
			this.type = type;
			this.addr = addr;
			this.user = user;
			this.pwd = pwd;
			this.auth = auth;
		}

		public Type type() { return Type.from(type); }

		public IndividualAddress address() { return addr; }

		/**
		 * Returns the user ID of this interface, or {@code 0} if no user was assigned.
		 *
		 * @return user as unsigned int, {@code 0 ≤ user < 128}
		 */
		public int user() { return user; }

		/**
		 * Returns the optional encrypted user password required to use this interface.
		 *
		 * @return optional encrypted password as byte array
		 */
		public Optional<byte[]> password() { return optional(pwd); }

		/**
		 * Returns the optional encrypted device authentication code of this interface.
		 *
		 * @return optional encrypted authentication code as byte array
		 */
		public Optional<byte[]> authentication() { return optional(auth); }

		/**
		 * Returns the group addresses linked with this interface, each with its set of group senders.
		 *
		 * @return group addresses, mapped to their (empty) set of senders
		 */
		public Map<GroupAddress, Set<IndividualAddress>> groups() { return groups; }

		/**
		 * Returns an interface with decrypted keys.
		 *
		 * @param keyringPwd keyring password
		 * @return DecryptedInterface with decrypted keys of this interface
		 * @throws KnxSecureException if password or authentication is not available, or decryption fails
		 */
		public DecryptedInterface decrypt(final char[] keyringPwd) {
			final var encUserPwd = password()
					.orElseThrow(() -> new KnxSecureException("no user password set for interface " + addr));
			final var decUserPwd = keyring.decryptPassword(encUserPwd, keyringPwd);
			final var userKey = SecureConnection.hashUserPassword(decUserPwd);

			final byte[] encDevAuth = authentication()
					.orElseThrow(() -> new KnxSecureException("no device authentication code set for interface " + addr));
			final char[] decDevAuth = keyring.decryptPassword(encDevAuth, keyringPwd);
			final var deviceAuthCode = SecureConnection.hashDeviceAuthenticationPassword(decDevAuth);

			return new DecryptedInterface(type(), addr, user, userKey, deviceAuthCode);
		}

		@Override
		public boolean equals(final Object o) {
			if (this == o)
				return true;
			if (!(o instanceof Interface))
				return false;
			final var other = (Interface) o;
			return Objects.equals(addr, other.addr) && Arrays.equals(auth, other.auth)
					&& Objects.equals(groups, other.groups) && Arrays.equals(pwd, other.pwd)
					&& Objects.equals(type, other.type) && user == other.user;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(auth);
			result = prime * result + Arrays.hashCode(pwd);
			result = prime * result + Objects.hash(addr, groups, type, user);
			return result;
		}

		@Override
		public String toString() {
			final int limit = 8;
			final var entries = groups.size() > limit ? groups.keySet().stream().limit(limit)
					.map(GroupAddress::toString).collect(Collectors.joining(", ", "[", ", ...]")) : groups.keySet();
			return type + " interface " + addr + ", user " + user + ", groups " + entries;
		}
	}

	/**
	 * An {@link Interface} with decrypted keys.
	 */
	/* public record */
	public static final class DecryptedInterface {
		private final Type type;
		private final IndividualAddress address;
		private final int user;
		private final byte[] userKey;
		private final byte[] deviceAuthCode;

		DecryptedInterface(final Type type, final IndividualAddress address, final int user, final byte[] userKey,
				final byte[] deviceAuthCode) {
			this.type = type;
			this.address = address;
			this.user = user;
			this.userKey = userKey;
			this.deviceAuthCode = deviceAuthCode;
		}

		public Interface.Type type() { return type; }

		public IndividualAddress address() { return address; }

		public int user() { return user; }

		public byte[] userKey() { return userKey.clone(); }

		public byte[] deviceAuthCode() { return deviceAuthCode.clone(); }

		@Override
		public String toString() { return type + " interface " + address + ", user " + user; }
	}

	public static final class Device {
		private final IndividualAddress addr;
		private final byte[] toolkey;
		private final byte[] pwd;
		private final byte[] auth;
		private final long sequence;

		Device(final IndividualAddress addr, final byte[] toolkey, final byte[] pwd, final byte[] auth,
			final long sequence) {
			this.addr = addr;
			this.toolkey = toolkey;
			this.pwd = pwd;
			this.auth = auth;
			this.sequence = sequence;
		}

		/**
		 * Returns the optional encrypted tool key of this device.
		 *
		 * @return optional tool key byte array of length 32
		 */
		public Optional<byte[]> toolKey() { return optional(toolkey); }

		/**
		 * Returns the optional encrypted management password of this device.
		 *
		 * @return optional byte array containing encrypted password
		 */
		public Optional<byte[]> password() { return optional(pwd); }

		/**
		 * Returns the optional encrypted authentication code of this device.
		 *
		 * @return optional byte array containing encrypted authentication code
		 */
		public Optional<byte[]> authentication() { return optional(auth); }

		/**
		 * Returns the last known valid sequence number received by this device.
		 *
		 * @return sequence number as unsigned 6 byte
		 */
		public long sequenceNumber() { return sequence; }

		@Override
		public boolean equals(final Object o) {
			if (this == o)
				return true;
			if (!(o instanceof Device))
				return false;
			final var other = (Device) o;
			return Objects.equals(addr, other.addr) && Arrays.equals(auth, other.auth) && Arrays.equals(pwd, other.pwd)
					&& sequence == other.sequence && Arrays.equals(toolkey, other.toolkey);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(auth);
			result = prime * result + Arrays.hashCode(pwd);
			result = prime * result + Arrays.hashCode(toolkey);
			result = prime * result + Objects.hash(addr, sequence);
			return result;
		}

		@Override
		public String toString() { return "device " + addr + " (seq " + sequence + ")"; }
	}

	public static final class Backbone {
		private final InetAddress mcGroup;
		private final byte[] groupKey;
		private final Duration latency;

		Backbone(final InetAddress multicastGroup, final byte[] groupKey, final Duration latency) {
			this.mcGroup = multicastGroup;
			this.groupKey = groupKey;
			this.latency = latency;
		}

		public InetAddress multicastGroup() { return mcGroup; }

		public Optional<byte[]> groupKey() { return optional(groupKey); }

		public Duration latencyTolerance() { return latency; }

		@Override
		public boolean equals(final Object o) {
			if (this == o)
				return true;
			if (!(o instanceof Backbone))
				return false;
			final var other = (Backbone) o;
			return Objects.equals(mcGroup, other.mcGroup) && Objects.equals(latency, other.latency)
					&& Arrays.equals(groupKey, other.groupKey);
		}

		@Override
		public int hashCode() { return Objects.hash(mcGroup, Arrays.hashCode(groupKey), latency); }

		@Override
		public String toString() {
			return multicastGroup().getHostAddress() + " (latency tolerance " + latency.toMillis() + " ms)";
		}
	}

	private static Optional<byte[]> optional(final byte[] ba) { return Optional.ofNullable(ba).map(byte[]::clone); }


	private static final String keyringNamespace = "http://knx.org/xml/keyring/1";
	private static final byte[] keyringSalt = utf8Bytes("1.keyring.ets.knx.org");

	private static final byte[] emptyPwd = new byte[0];

	private static final Logger logger = LogService.getLogger("calimero.keyring");

	private final String keyringUri;
	private final char[] keyringPassword;

	private byte[] passwordHash = {};
	private byte[] createdHash = {};

	private byte[] signature;

	private volatile String project;
	private volatile Backbone backbone;
	// TODO clarify the use of optional field 'host' for interface types Backbone/USB
	// this mapping works for tunneling interfaces: host -> Interface
	private volatile Map<IndividualAddress, List<Interface>> interfaces = Map.of();
	private volatile Map<GroupAddress, byte[]> groups = Map.of();
	private volatile Map<IndividualAddress, Device> devices = Map.of();


	/**
	 * Loads an ETS keyring file given by its URI. Loading a keyring does not decrypt any encrypted data.
	 *
	 * @param keyringUri keyring location identifier, the XML resource name has to end with ".knxkeys"
	 * @return new Keyring instance containing the keyring information
	 * @throws KNXMLException on XML parsing errors, or keyring elements deviating from the expected or requested
	 *         format
	 * @throws KnxSecureException for cryptographic setup/algorithm problems
	 * @see #verifySignature(char[])
	 */
	public static Keyring load(final String keyringUri) {
		final var keyring = new Keyring(keyringUri, new char[0]);
		keyring.load();
		return keyring;
	}

	Keyring(final String keyringUri, final char[] keyringPassword) {
		if (!keyringUri.endsWith(".knxkeys"))
			throw new KNXIllegalArgumentException("'" + keyringUri + "' is not a keyring file");

		this.keyringUri = keyringUri;
		this.keyringPassword = keyringPassword;
	}

	void load() {
		int line = 0;
		try (var reader = XmlInputFactory.newInstance().createXMLReader(keyringUri)) {
			// call nextTag() to dive straight into first element, so we can check the keyring namespace
			reader.nextTag();

			final var namespace = reader.getNamespaceURI();
			if (!keyringNamespace.equals(namespace))
				throw new KNXMLException("keyring '" + keyringUri + "' with unsupported namespace '" + namespace + "'");

			if (!"Keyring".equals(reader.getLocalName()))
				throw new KNXMLException("keyring '" + keyringUri + "' requires 'Keyring' element");

			project = reader.getAttributeValue(null, "Project");
			final var createdBy = reader.getAttributeValue(null, "CreatedBy");
			final var created = reader.getAttributeValue(null, "Created");
			logger.log(DEBUG, "read keyring for project ''{0}'', created by {1} on {2}", project, createdBy, created);

			passwordHash = hashKeyringPwd(keyringPassword);
			createdHash = sha256(utf8Bytes(created));

			signature = decode(reader.getAttributeValue(null, "Signature"));

			if (keyringPassword.length > 0) {
				if (!verifySignature(passwordHash)) {
					final String msg = "signature verification failed for keyring '" + keyringUri + "'";
					final boolean strictVerification = true;
					if (strictVerification)
						throw new KnxSecureException(msg);
					logger.log(WARNING, msg);
				}
			}

			Interface iface = null;
			boolean inDevices = false;
			boolean inGroupAddresses = false;

			final Map<IndividualAddress, List<Interface>> interfaces = new HashMap<>();
			final Map<GroupAddress, byte[]> groups = new HashMap<>();
			final Map<IndividualAddress, Device> devices = new HashMap<>();

			for (reader.next(); reader.getEventType() != XmlReader.END_DOCUMENT; reader.next()) {
				final var event = reader.getEventType();

				if (reader.getEventType() != XmlReader.START_ELEMENT) {
					if (event == XmlReader.END_ELEMENT && "Interface".equals(reader.getLocalName()) && iface != null) {
						iface.groups = Map.copyOf(iface.groups);
						logger.log(TRACE, "add {0}", iface);
						iface = null;
					}
					continue;
				}

				final var name = reader.getLocalName();
				line = reader.getLocation().getLineNumber();
				if ("Backbone".equals(name)) { // [0, 1]
					final var mcastGroup = InetAddress.getByName(reader.getAttributeValue(null, "MulticastAddress"));
					if (!validRoutingMulticast(mcastGroup))
						throw new KNXMLException("loading keyring '" + keyringUri + "': " + mcastGroup.getHostAddress()
								+ " is not a valid KNX multicast address");

					String val = reader.getAttributeValue(null, "Key");
					final var groupKey = val != null ? decode(val) : null;

					val = reader.getAttributeValue(null, "Latency");
					final var latency = val != null ? Duration.ofMillis(Integer.parseInt(val)) : Duration.ZERO;

					backbone = new Backbone(mcastGroup, groupKey, latency);
				}
				else if ("Interface".equals(name)) { // [0, *]
					inGroupAddresses = false;

					final var type = reader.getAttributeValue(null, "Type"); // { Backbone, Tunneling, USB }
					// rest is optional
					String attr = reader.getAttributeValue(null, "Host");
					final var host = attr != null ? new IndividualAddress(attr) : new IndividualAddress(0);
					attr = reader.getAttributeValue(null, "IndividualAddress");
					final var addr = attr != null ? new IndividualAddress(attr) : new IndividualAddress(0);
					final var user = readAttribute(reader, "UserID", Integer::parseInt, 0);
					final var pwd = readAttribute(reader, "Password", Keyring::decode, null);
					final var auth = readAttribute(reader, "Authentication", Keyring::decode, null);

					iface = new Interface(this, type, addr, user, pwd, auth);
					interfaces.computeIfAbsent(host, key -> new ArrayList<>()).add(iface);

				}
				else if (iface != null && "Group".equals(name)) { // [0, *]
					final var addr = new GroupAddress(reader.getAttributeValue(null, "Address"));

					final var senders = reader.getAttributeValue(null, "Senders"); // optional, (empty) list of addresses
					final var list = new ArrayList<IndividualAddress>();
					if (senders != null) {
						final Matcher matcher = Pattern.compile("[^\\s]+").matcher(senders);
						while (matcher.find())
							list.add(new IndividualAddress(matcher.group()));
					}

					if (iface.groups.isEmpty())
						iface.groups = new HashMap<>();
					iface.groups.put(addr, Set.of(list.toArray(new IndividualAddress[0])));
				}
				else if ("Devices".equals(name)) {
					inDevices = true;
				}
				else if (inDevices && "Device".equals(name)) { // [0, *]
					final var addr = new IndividualAddress(reader.getAttributeValue(null, "IndividualAddress"));
					// rest is optional
					final var toolkey = readAttribute(reader, "ToolKey", Keyring::decode, null);
					final var seq = readAttribute(reader, "SequenceNumber", Long::parseLong, (long) 0);
					final var pwd = readAttribute(reader, "ManagementPassword", Keyring::decode, null);
					final var auth = readAttribute(reader, "Authentication", Keyring::decode, null);

					final var device = new Device(addr, toolkey, pwd, auth, seq);
					devices.put(addr, device);
					logger.log(TRACE, "add {0}", device);
				}
				else if ("GroupAddresses".equals(name)) {
					inGroupAddresses = true;
				}
				else if (inGroupAddresses && "Group".equals(name)) { // [0, *]
					final var addr = new GroupAddress(reader.getAttributeValue(null, "Address"));
					final var key = decode(reader.getAttributeValue(null, "Key"));
					groups.put(addr, key);
				}
				else
					logger.log(WARNING, "keyring ''{0}'': skip unknown element ''{1}''", keyringUri, name);
			}

			this.interfaces = Map.copyOf(interfaces);
			this.groups = Map.copyOf(groups);
			this.devices = Map.copyOf(devices);
		}
		catch (KNXFormatException | UnknownHostException e) {
			final String location = line != 0 ? " [line " + line + "]" : "";
			throw new KNXMLException(
					"loading keyring '" + keyringUri + "'" + location + " address element with " + e.getMessage());
		}
		catch (final GeneralSecurityException e) {
			// NoSuchAlgorithmException, InvalidKeySpecException etc. imply a setup/programming error
			throw new KnxSecureException("crypto error", e);
		}
		finally {
			Arrays.fill(passwordHash, (byte) 0);
		}
	}

	/**
	 * Verifies the keyring signature using the supplied keyring password.
	 *
	 * @param keyringPassword keyring password used for keyring encryption
	 * @return {@code true} if signature is valid, {@code false} otherwise
	 * @throws KNXMLException on XML parsing errors during signature verification
	 * @throws KnxSecureException if generating the secret key for the password hash fails
	 */
	public boolean verifySignature(final char[] keyringPassword) {
		try {
			return verifySignature(hashKeyringPwd(keyringPassword));
		}
		catch (final GeneralSecurityException e) {
			return false;
		}
	}

	public Optional<Backbone> backbone() { return Optional.ofNullable(backbone); }

	public Map<IndividualAddress, List<Interface>> interfaces() { return interfaces; }

	public Map<GroupAddress, byte[]> groups() { return groups; }

	public Map<IndividualAddress, Device> devices() { return devices; }

	private boolean verifySignature(final byte[] passwordHash) throws GeneralSecurityException {
		final var output = new ByteArrayOutputStream();
		try (var reader = XmlInputFactory.newInstance().createXMLReader(keyringUri)) {
			while (reader.next() != XmlReader.END_DOCUMENT) {
				if (reader.getEventType() == XmlReader.START_ELEMENT)
					appendElement(reader, output);
				else if (reader.getEventType() == XmlReader.END_ELEMENT)
					output.write(2);
			}
		}

		appendString(Base64.getEncoder().encode(passwordHash), output);

		final byte[] outputHash = sha256(output.toByteArray());
		return Arrays.equals(outputHash, signature);
	}

	/**
	 * Decrypts a backbone key, tool key, or group address key using the keyring password.
	 *
	 * @param input encrypted key
	 * @param keyringPassword the password of this keyring
	 * @return decrypted key as byte array
	 * @throws KnxSecureException for cryptographic setup/algorithm problems
	 */
	public byte[] decryptKey(final byte[] input, final char[] keyringPassword) {
		final var pwdHash = hashKeyringPwd(keyringPassword);
		try {
			return aes128Cbc(input, pwdHash, createdHash);
		}
		catch (GeneralSecurityException | RuntimeException e) {
			throw new KnxSecureException("decrypting key data", e);
		}
		finally {
			Arrays.fill(pwdHash, (byte) 0);
		}
	}

	/**
	 * Decrypts a user password, device authentication code, or management (commissioning) password using the keyring
	 * password.
	 *
	 * @param input encrypted password
	 * @param keyringPassword the password of this keyring
	 * @return decrypted password as char array
	 * @throws KnxSecureException for cryptographic setup/algorithm problems
	 */
	public char[] decryptPassword(final byte[] input, final char[] keyringPassword) {
		final var keyringPwdHash = hashKeyringPwd(keyringPassword);
		try {
			final byte[] pwdData = extractPassword(aes128Cbc(input, keyringPwdHash, createdHash));
			final var chars = new char[pwdData.length];
			for (int i = 0; i < pwdData.length; i++)
				chars[i] = (char) (pwdData[i] & 0xff);
			Arrays.fill(pwdData, (byte) 0);
			return chars;
		}
		catch (GeneralSecurityException | RuntimeException e) {
			throw new KnxSecureException("decrypting password data", e);
		}
		finally {
			Arrays.fill(keyringPwdHash, (byte) 0);
		}
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o)
			return true;
		if (!(o instanceof Keyring))
			return false;
		final var other = (Keyring) o;

		if (Arrays.equals(signature, other.signature))
			return true;

		return project.equals(other.project) && backbone.equals(other.backbone) && interfaces.equals(other.interfaces)
				&& groupsEquals(other.groups) && devices.equals(other.devices);
	}

	@Override
	public int hashCode() {
		return Objects.hash(project, backbone, interfaces, groupsHashCode(), devices);
	}

	@Override
	public String toString() {
		return String.format("'%s' backbone: %s, interfaces: %s, group addresses: %d, devices: %d", project, backbone,
				interfaces.keySet(), groups.size(), devices.size());
	}

	// need this because groups map values are of type byte[]
	private boolean groupsEquals(final Map<GroupAddress, byte[]> other) {
		return (groups.size() == other.size()
				&& groups.entrySet().stream().allMatch(e -> Arrays.equals(e.getValue(), other.get(e.getKey()))));
	}

	// need this because groups map values are of type byte[]
	private int groupsHashCode() {
		final int prime = 31;
		int result = 1;
		for (final var e : groups.entrySet()) {
			result = prime * result + e.getKey().hashCode();
			result = prime * result + Arrays.hashCode(e.getValue());
		}
		return result;
	}

	private static final long DefaultMulticast = unsigned(new byte[] { (byte) 224, 0, 23, 12 });

	private static boolean validRoutingMulticast(final InetAddress address) {
		return address != null && address.isMulticastAddress() && unsigned(address.getAddress()) >= DefaultMulticast;
	}

	private static long unsigned(final byte[] data) {
		long l = 0;
		for (final byte b : data)
			l = l << 8 | (b & 0xff);
		return l;
	}

	private static <R> R readAttribute(final XmlReader reader, final String attribute, final Function<String, R> parser,
			final R defaultValue) {
		final var attr = reader.getAttributeValue(null, attribute);
		if (attr == null)
			return defaultValue;
		return parser.apply(attr);
	}

	private static void appendElement(final XmlReader reader, final ByteArrayOutputStream output) {
		output.write(1);
		appendString(utf8Bytes(reader.getLocalName()), output);

		IntStream.range(0, reader.getAttributeCount()).mapToObj(reader::getAttributeLocalName)
				.filter(not(isEqual("xmlns").or(isEqual("Signature")))).sorted()
				.forEach(attr -> appendAttribute(attr, reader, output));
	}

	private static void appendAttribute(final String attr, final XmlReader reader, final ByteArrayOutputStream output) {
		appendString(utf8Bytes(attr), output);
		appendString(utf8Bytes(reader.getAttributeValue(null, attr)), output);
	}

	private static void appendString(final byte[] str, final ByteArrayOutputStream output) {
		output.write(str.length);
		output.write(str, 0, str.length);
	}

	private static byte[] decode(final String base64) {
		return Base64.getDecoder().decode(base64);
	}

	private static byte[] extractPassword(final byte[] data) {
		if (data.length == 0)
			return emptyPwd;
		final int b = data[data.length - 1] & 0xff;
		final byte[] range = Arrays.copyOfRange(data, 8, data.length - b);
		return range;
	}

	private static byte[] hashKeyringPwd(final char[] keyringPwd) {
		try {
			return pbkdf2WithHmacSha256(keyringPwd, keyringSalt);
		}
		catch (final GeneralSecurityException e) {
			throw new KnxSecureException("hashing keyring password", e);
		}
	}

	private static byte[] aes128Cbc(final byte[] input, final byte[] key, final byte[] iv)
		throws GeneralSecurityException {

		final var cipher = Cipher.getInstance("AES/CBC/NoPadding");
		final var keySpec = new SecretKeySpec(key, "AES");
		final var params = new IvParameterSpec(iv);

		cipher.init(Cipher.DECRYPT_MODE, keySpec, params);
		return cipher.doFinal(input);
	}

	private static byte[] sha256(final byte[] input) throws NoSuchAlgorithmException {
		final var digest = MessageDigest.getInstance("SHA-256");
		digest.update(input);
		return Arrays.copyOf(digest.digest(), 16);
	}

	private static byte[] pbkdf2WithHmacSha256(final char[] password, final byte[] salt)
			throws GeneralSecurityException {
		if (password.length == 0)
			return new byte[0];

		final int iterations = 65_536;
		final int keyLength = 16;
		return deriveKey(password, salt, iterations, keyLength);
	}

	private static byte[] deriveKey(final char[] pwd, final byte[] salt, final int iterations, final int size)
			throws NoSuchAlgorithmException, InvalidKeyException {
		final var mac = hmac("HmacSHA256", macKey(pwd));

		mac.update(salt);
		final byte[] blockIdx = new byte[] { 0, 0, 0, 1 };
		byte[] input = mac.doFinal(blockIdx);
		final byte[] output = new byte[size];
		for (int i = 0; i < iterations; ++i) {
			for (int s = 0; s < size; ++s)
				output[s] ^= input[s];
			input = mac.doFinal(input);
		}
		return output;
	}

	private static byte[] macKey(final char[] pwd) {
		final var buffer = StandardCharsets.US_ASCII.encode(CharBuffer.wrap(pwd));
		final int len = buffer.remaining();
		final byte[] macKey = new byte[len];
		buffer.get(macKey);
		buffer.clear().put(new byte[len]);
		return macKey;
	}

	private static Mac hmac(final String algorithm, final byte[] key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		final var mac = Mac.getInstance(algorithm);
		mac.init(new SecretKeySpec(key, algorithm));
		return mac;
	}

	private static byte[] utf8Bytes(final String s) {
		return s.getBytes(StandardCharsets.UTF_8);
	}
}
