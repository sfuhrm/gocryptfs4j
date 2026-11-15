package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.generators.SCrypt;
import org.jspecify.annotations.Nullable;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * Key derivation and random-byte helpers.
 */
public final class Keys {

    /** The shared source of cryptographically secure random bytes. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Prevents instantiation. */
    private Keys() {
    }

    /**
     * Derives a key using scrypt (RFC 7914), identical to
     * {@code golang.org/x/crypto/scrypt}.
     *
     * <p><b>Memory-hygiene caveat.</b> scrypt is built on HMAC-SHA256, and the
     * HMAC key schedule copies the password into the digest's internal state
     * (Bouncy Castle's {@code SCrypt} does this inside its PBKDF2 step). That
     * copy is not wiped when derivation finishes and cannot be reached through
     * any public API; it is only released when the heap object is eventually
     * garbage collected. Wiping {@code password} after this call therefore
     * clears the caller's buffer but not this internal copy. This is inherent
     * to HMAC-based scrypt &mdash; the JDK's own {@code Mac} copies its key the
     * same way &mdash; so it is not a defect specific to this method.</p>
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
     * Fills {@code buffer} with cryptographically secure random bytes.
     *
     * @param buffer the buffer to fill
     * @throws NullPointerException if {@code buffer} is {@code null}
     */
    public static void randomBytes(byte[] buffer) {
        Objects.requireNonNull(buffer, "buffer");
        RANDOM.nextBytes(buffer);
    }

    /**
     * Wipes the contents of a sensitive buffer.
     *
     * @param buf the buffer to wipe, or {@code null}
     */
    public static void wipe(byte @Nullable [] buf) {
        if (buf != null) {
            java.util.Arrays.fill(buf, (byte) 0);
        }
    }
}
