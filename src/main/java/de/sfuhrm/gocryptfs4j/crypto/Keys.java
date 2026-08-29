package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.generators.SCrypt;

import java.security.SecureRandom;

/**
 * Key derivation and random-byte helpers.
 */
public final class Keys {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Keys() {
    }

    /**
     * Derives a key using scrypt (RFC 7914), identical to
     * {@code golang.org/x/crypto/scrypt}.
     *
     * @param password password bytes
     * @param salt     salt bytes
     * @param n        CPU/memory cost parameter
     * @param r        block size parameter
     * @param p        parallelization parameter
     * @param keyLen   desired output length in bytes
     */
    public static byte[] scrypt(byte[] password, byte[] salt, int n, int r, int p, int keyLen) {
        return SCrypt.generate(password, salt, n, r, p, keyLen);
    }

    /** Fills {@code buf} with cryptographically secure random bytes. */
    public static byte[] randomBytes(int len) {
        byte[] buf = new byte[len];
        RANDOM.nextBytes(buf);
        return buf;
    }

    /** Wipes the contents of a sensitive buffer. */
    public static void wipe(byte[] buf) {
        if (buf != null) {
            java.util.Arrays.fill(buf, (byte) 0);
        }
    }
}
