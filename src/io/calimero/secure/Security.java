/*
    Calimero - A library for KNX network access
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

package io.calimero.secure;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import io.calimero.GroupAddress;
import io.calimero.IndividualAddress;
import io.calimero.SerialNumber;
import io.calimero.secure.Keyring.Interface;

/**
 * Contains key and address information required for KNX secure process communication and management.
 */
public final class Security {

	private static final Security defInst = new Security();

	private final Map<IndividualAddress, byte[]> deviceToolKeys = new ConcurrentHashMap<>();
	private final Map<GroupAddress, byte[]> groupKeys = new ConcurrentHashMap<>();
	private final Map<GroupAddress, Set<IndividualAddress>> groupSenders = new ConcurrentHashMap<>();
	private final Map<IndividualAddress, Map<GroupAddress, Set<IndividualAddress>>> sendersByInterface = new ConcurrentHashMap<>();
	private final Map<SerialNumber, byte[]> broadcastToolKeys = new ConcurrentHashMap<>();


	/**
	 * Creates a new security object, mainly for use with KNX installations other than the {@link #defaultInstallation()}.
	 */
	public static Security newSecurity() { return new Security(); }

	static Security withKeys(final Map<IndividualAddress, byte[]> deviceToolKeys,
			final Map<GroupAddress, byte[]> groupKeys, final Map<GroupAddress, Set<IndividualAddress>> groupSenders) {
		final var s = new Security();
		s.deviceToolKeys.putAll(deviceToolKeys);
		s.groupKeys.putAll(groupKeys);
		s.groupSenders.putAll(groupSenders);
		return s;
	}

	/**
	 * Returns the security object for the default KNX installation.
	 *
	 * @return instance used for default KNX installation
	 */
	// ??? naming: knx installation id is linked to project id and not stored in keyring nor in many interfaces
	public static Security defaultInstallation() { return defInst; }


	private Security() {}

	/**
	 * Adds KNX secure information of the supplied keyring to this security instance;
	 * keyring entries will overwrite existing key data.
	 *
	 * @param keyring keyring to add, keyring has to have a valid signature
	 * @param password keyring password
	 */
	public void useKeyring(final Keyring keyring, final char[] password) {
		if (!keyring.verifySignature(password))
			throw new KnxSecureException("keyring signature mismatch (invalid keyring or wrong password)");

		final var devices = keyring.devices();
		devices.forEach((addr, device) -> device.toolKey().ifPresent(
				toolkey -> deviceToolKeys.put(addr, keyring.decryptKey(toolkey, password))));

		keyring.groups().forEach((addr, key) -> groupKeys.put(addr, keyring.decryptKey(key, password)));


		final var interfaceAddresses = keyring.interfaces().values().stream().flatMap(List::stream)
				.map(Interface::address).collect(Collectors.toSet());

		for (final var interfaces : keyring.interfaces().values()) {
			for (final var i : interfaces) {
				for (final var entry : i.groups().entrySet()) {
					final var senders = groupSenders.computeIfAbsent(entry.getKey(),
							__ -> ConcurrentHashMap.newKeySet());
					entry.getValue().stream().filter(Predicate.not(interfaceAddresses::contains)).forEach(senders::add);
				}
			}
		}

		keyring.interfaces().values().stream().flatMap(List::stream)
				.forEach(entry -> sendersByInterface.put(entry.address(), mutableMapOf(entry.groups())));
	}

	private static <T> Set<T> concurrentSetOf(final Set<T> t) {
		final var set = ConcurrentHashMap.<T> newKeySet();
		set.addAll(t);
		return set;
	}

	@SuppressWarnings("unchecked")
	private static <K, V extends Set<T>, T> Map<K, V> mutableMapOf(final Map<K, V> m) {
		final var map = new ConcurrentHashMap<K, V>();
		m.forEach((k, v) -> map.put(k, (V) concurrentSetOf(v)));
		return map;
	}

	/**
	 * Returns the device toolkeys currently configured for this security object.
	 *
	 * @return modifiable mapping of device address to tool key
	 */
	public Map<IndividualAddress, byte[]> deviceToolKeys() {
		return deviceToolKeys;
	}

	/**
	 * Returns the group keys currently configured for this security object.
	 *
	 * @return modifiable mapping of group address to group key
	 */
	public Map<GroupAddress, byte[]> groupKeys() {
		return groupKeys;
	}

	/**
	 * Returns the secure datapoints currently configured for this security object, together with the addresses
	 * of devices acting as senders for that specific datapoint.
	 *
	 * @return modifiable mapping of group address to set of senders
	 */
	public Map<GroupAddress, Set<IndividualAddress>> groupSenders() {
		return groupSenders;
	}

	/**
	 * Returns the group addresses and group senders currently configured for a specific secure interface.
	 * Group senders are addresses of devices acting as senders for a specific datapoint.
	 *
	 * @return modifiable mapping of group address to set of group senders, the map might be empty
	 */
	public Map<GroupAddress, Set<IndividualAddress>> groupSenders(final IndividualAddress interfaceAddress) {
		return sendersByInterface.computeIfAbsent(interfaceAddress, __ -> new ConcurrentHashMap<>());
	}

	Map<SerialNumber, byte[]> broadcastToolKeys() { return broadcastToolKeys; }
}
