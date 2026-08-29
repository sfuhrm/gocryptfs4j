package de.sfuhrm.gocryptfs4j.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * HKDF-SHA256 (RFC 5869) as used by gocryptfs to derive sub-keys from the
 * master key.
 *
 * gocryptfs calls {@code hkdf.Key(sha256.New, masterkey, nil, info, outLen)},
 * i.e. with an empty (all-zero) salt.
 */
public final class Hkdf {

    private static final int HASH_LEN = 32; // SHA-256

    private Hkdf() {
    }

    /**
     * Derives {@code outLen} bytes from {@code ikm} using HKDF-SHA256 with an
     * empty salt and the given {@code info}.
     */
    public static byte[] derive(byte[] ikm, String info, int outLen) {
        try {
            byte[] salt = new byte[HASH_LEN];
            byte[] prk = hmac(salt, ikm);

            byte[] okm = new byte[outLen];
            byte[] t = new byte[0];
            byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
            int pos = 0;
            int counter = 1;
            while (pos < outLen) {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(t);
                mac.update(infoBytes);
                mac.update((byte) counter);
                t = mac.doFinal();
                int copyLen = Math.min(t.length, outLen - pos);
                System.arraycopy(t, 0, okm, pos, copyLen);
                pos += copyLen;
                counter++;
            }
            return okm;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF failed", e);
        }
    }

    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }
}
