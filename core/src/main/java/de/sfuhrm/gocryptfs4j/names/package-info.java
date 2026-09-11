/**
 * Encryption of file names using AES-EME with a per-directory IV.
 *
 * <p>{@link NameTransform} encrypts plaintext names with EME wide-block
 * encryption under the directory IV, base64url-encodes the result, and handles
 * gocryptfs long-name handling: names whose encrypted form exceeds the limit
 * are hashed to a {@code gocryptfs.longname.&hellip;} content store plus a
 * {@code .name} support file.</p>
 *
 * <p>The classes in this package are implementation details and are not part of
 * the public API; use {@code de.sfuhrm.gocryptfs4j.core.GocryptFs} instead.</p>
 */
package de.sfuhrm.gocryptfs4j.names;
