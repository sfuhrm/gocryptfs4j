package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.generators.SCrypt;

import java.security.SecureRandom;
import java.util.Objects;

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
     * @return the derived key
     * @throws NullPointerException if {@code password} or {@code salt} is {@code null}
     * @throws IllegalArgumentException if {@code n}, {@code r} or {@code p} is not positive,
     *                                  or {@code keyLen} is negative
     */
    public static byte[] scrypt(byte[] password, byte[] salt, int n, int r, int p, int keyLen) {
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(salt, "salt");
        if (n <= 0 || r <= 0 || p <= 0) {
            throw new IllegalArgumentException("scrypt parameters must be positive: n="
                    + n + " r=" + r + " p=" + p);
        }
        if (keyLen < 0) {
            throw new IllegalArgumentException("negative key length: " + keyLen);
        }
        return SCrypt.generate(password, salt, n, r, p, keyLen);
    }

    /**
     * Returns a buffer of cryptographically secure random bytes.
     *
     * @param len the number of random bytes
     * @return the random bytes
     * @throws IllegalArgumentException if {@code len} is negative
     */
    public static byte[] randomBytes(int len) {
        if (len < 0) {
            throw new IllegalArgumentException("negative length: " + len);
        }
        byte[] buf = new byte[len];
        RANDOM.nextBytes(buf);
        return buf;
    }

    /**
     * Wipes the contents of a sensitive buffer.
     *
     * @param buf the buffer to wipe, or {@code null}
     */
    public static void wipe(byte[] buf) {
        if (buf != null) {
            java.util.Arrays.fill(buf, (byte) 0);
        }
    }
}
