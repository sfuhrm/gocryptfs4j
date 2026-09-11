/**
 * Reading, writing and unlocking of the {@code gocryptfs.conf} configuration
 * file.
 *
 * <p>{@link ConfigFile} models the JSON configuration that gocryptfs stores in
 * the cipher directory: the scrypt parameters, feature flags (HKDF, diriv, name
 * encryption, cipher selection, &hellip;) and the encrypted master key.
 * {@link ConfigFile#decryptMasterKey(char[])} unlocks the master key from a
 * password, and {@link ConfigFile#reencryptMasterKey(byte[], char[])} is the
 * equivalent of gocryptfs's {@code -passwd}. {@link ScryptKdf} holds the scrypt
 * key-derivation parameters.</p>
 *
 * <p>The classes in this package are implementation details and are not part of
 * the public API; use {@code de.sfuhrm.gocryptfs4j.core.GocryptFs} instead.</p>
 */
package de.sfuhrm.gocryptfs4j.config;
