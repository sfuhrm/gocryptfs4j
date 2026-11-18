package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * HKDF-SHA256 (RFC 5869) as used by gocryptfs to derive sub-keys from the
 * master key.
 *
 * gocryptfs calls {@code hkdf.Key(sha256.New, masterkey, nil, info, outLen)},
 * that is, with an empty (all-zero) salt.
 */
public final class Hkdf {

    /** The SHA-256 output length in bytes. */
    private static final int HASH_LEN = 32; // SHA-256

    /**
     * The maximum derivable output length: the HKDF counter is a single byte,
     * so at most 255 blocks of {@link #HASH_LEN} bytes can be produced.
     */
    private static final int MAX_OUT_LEN = 255 * HASH_LEN;

    /** Prevents instantiation. */
    private Hkdf() {
    }

    /**
     * Derives {@code outLen} bytes from {@code ikm} using HKDF-SHA256 with an
     * empty salt and the given {@code info}.
     *
     * @param ikm    the input keying material
     * @param info   the context and application-specific information
     * @param outLen the desired output length in bytes
     * @return the derived key
     * @throws NullPointerException if {@code ikm} or {@code info} is {@code null}
     * @throws IllegalArgumentException if {@code outLen} is negative or exceeds
     *                                  {@value #MAX_OUT_LEN}
     */
    public static byte[] derive(byte[] ikm, String info, int outLen) {
        Objects.requireNonNull(ikm, "ikm");
        Objects.requireNonNull(info, "info");
        if (outLen < 0) {
            throw new IllegalArgumentException("negative output length: " + outLen);
        }
        if (outLen > MAX_OUT_LEN) {
            throw new IllegalArgumentException("output length exceeds HKDF limit "
                    + MAX_OUT_LEN + ": " + outLen);
        }
        byte[] salt = new byte[HASH_LEN];
        byte[] prk = null;
        byte[] t = new byte[0];
        KeyParameter saltKey = new KeyParameter(salt);
        KeyParameter prkKey = null;
        HMac mac = new HMac(SHA256Digest.newInstance());
        try {
            mac.init(saltKey);
            mac.update(ikm, 0, ikm.length);
            prk = new byte[mac.getMacSize()];
            mac.doFinal(prk, 0);
            Arrays.fill(saltKey.getKey(), (byte) 0);

            prkKey = new KeyParameter(prk);
            mac.init(prkKey);

            byte[] okm = new byte[outLen];
            byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
            int pos = 0;
            int counter = 1;
            while (pos < outLen) {
                mac.update(t, 0, t.length);
                mac.update(infoBytes, 0, infoBytes.length);
                mac.update((byte) counter);
                byte[] next = new byte[mac.getMacSize()];
                mac.doFinal(next, 0);
                Keys.wipe(t);
                t = next;
                int copyLen = Math.min(t.length, outLen - pos);
                System.arraycopy(t, 0, okm, pos, copyLen);
                pos += copyLen;
                counter++;
            }
            return okm;
        } finally {
            Keys.wipe(salt);
            Keys.wipe(prk);
            Keys.wipe(t);
            if (saltKey != null) {
                Arrays.fill(saltKey.getKey(), (byte) 0);
            }
            if (prkKey != null) {
                Arrays.fill(prkKey.getKey(), (byte) 0);
            }
            wipeMac(mac);
        }
    }

    /**
     * Re-initializes an HMAC with a zero key so its key schedule no longer holds
     * the real key, then wipes the zero-key parameter as well.
     *
     * @param mac the HMAC to clear
     */
    private static void wipeMac(HMac mac) {
        KeyParameter zero = new KeyParameter(new byte[HASH_LEN]);
        try {
            mac.init(zero);
        } finally {
            Arrays.fill(zero.getKey(), (byte) 0);
        }
    }
}
