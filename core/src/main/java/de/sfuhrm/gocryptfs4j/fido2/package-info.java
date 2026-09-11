/**
 * Abstraction for FIDO2-based master-key protection.
 *
 * <p>{@link Fido2Token} describes the two token operations gocryptfs4j needs to
 * read and write gocryptfs {@code -fido2} filesystems. The project deliberately
 * does not provide a concrete implementation; applications wire in their own
 * libfido2 or YubiKey SDK adapter.</p>
 */
package de.sfuhrm.gocryptfs4j.fido2;
