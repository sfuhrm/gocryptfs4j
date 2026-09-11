package de.sfuhrm.gocryptfs4j.fido2;

import java.io.IOException;
import java.util.List;

/**
 * Abstraction over a FIDO2 security token capable of the {@code hmac-secret}
 * extension, as used by gocryptfs's {@code -fido2} mode.
 *
 * <p>gocryptfs4j intentionally ships <em>no</em> concrete implementation: it does
 * not link against libfido2, the YubiKey SDK or any other native FIDO2 stack.
 * Instead, an application that wants FIDO2 protection implements this interface
 * on top of a library of its choice (for example the libfido2 command-line
 * tools {@code fido2-cred}/{@code fido2-assert}, or the YubiKey SDK) and passes
 * the implementation to
 * {@link de.sfuhrm.gocryptfs4j.core.GocryptFs#create(java.nio.file.Path, Fido2Token)}
 * or
 * {@link de.sfuhrm.gocryptfs4j.core.GocryptFs#open(java.nio.file.Path, Fido2Token)}.</p>
 *
 * <p>To stay byte-compatible with filesystems created by gocryptfs, the
 * implementation must register credentials with the relying-party ID
 * {@link #RELYING_PARTY_ID} and base its {@code hmac-secret} on the returned
 * credential ID and the salt supplied by gocryptfs4j. The raw secret returned by
 * {@link #hmacSecret(byte[], byte[], List)} is used directly as the scrypt
 * password that wraps the master key, so it must be stable for a given
 * credential and salt.</p>
 */
public interface Fido2Token {

    /**
     * The relying-party ID that gocryptfs uses for its credentials.
     */
    String RELYING_PARTY_ID = "gocryptfs";

    /**
     * Registers a new credential on the token that supports the
     * {@code hmac-secret} extension.
     *
     * <p>This is called once, when a filesystem is created. The returned
     * credential ID is stored in {@code gocryptfs.conf} and handed back to
     * {@link #hmacSecret(byte[], byte[], List)} on every open.</p>
     *
     * @param userName the user name to associate with the credential (gocryptfs
     *                 uses the base name of the cipher directory)
     * @return the raw credential ID, must not be {@code null}
     * @throws IOException if the token interaction fails
     */
    byte[] registerCredential(String userName) throws IOException;

    /**
     * Derives the {@code hmac-secret} for the given credential and salt.
     *
     * <p>The returned bytes are used verbatim as the scrypt password protecting
     * the master key. gocryptfs requires at least 32 bytes and rejects an
     * all-zero secret.</p>
     *
     * @param credentialId   the credential ID returned by
     *                       {@link #registerCredential(String)}
     * @param hmacSalt       the random salt stored in {@code gocryptfs.conf}
     * @param assertOptions  options to pass to the token assertion, never
     *                       {@code null} (may be empty)
     * @return the raw HMAC secret, must not be {@code null}
     * @throws IOException if the token interaction fails
     */
    byte[] hmacSecret(byte[] credentialId, byte[] hmacSalt, List<String> assertOptions)
            throws IOException;
}
