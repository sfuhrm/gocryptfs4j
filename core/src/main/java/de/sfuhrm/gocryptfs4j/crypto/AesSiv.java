package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * AES-SIV (RFC 5297) helper matching the {@code siv_aead} backend used by
 * gocryptfs: a 64-byte key, a 16-byte SIV and a 16-byte nonce, backed by
 * BouncyCastle's AES engine, CMAC and SIC (CTR) mode.
 *
 * <p>The SIV is derived from the plaintext, the nonce and the associated data
 * (S2V), then used as the CTR initial counter. The nonce is treated as the
 * last associated-data element, per RFC 5297 section 3, which is how gocryptfs
 * uses it.</p>
 */
public final class AesSiv implements ContentCipher {

    private final byte[] k1;
    private final byte[] k2;

    /**
     * Creates an AES-SIV instance.
     *
     * @param key the 64-byte key (split into two 32-byte halves)
     */
    public AesSiv(byte[] key) {
        if (key.length != Constants.SIV_KEY_LEN) {
            throw new IllegalArgumentException("AES-SIV key must be "
                    + Constants.SIV_KEY_LEN + " bytes");
        }
        this.k1 = Arrays.copyOfRange(key, 0, Constants.KEY_LEN);
        this.k2 = Arrays.copyOfRange(key, Constants.KEY_LEN, 2 * Constants.KEY_LEN);
    }

    /**
     * Encrypts {@code plaintext}, returning the 16-byte SIV followed by the
     * ciphertext.
     *
     * @param plaintext the plaintext to encrypt
     * @param nonce     the 16-byte nonce
     * @param aad       additional authenticated data, or {@code null}
     * @return the SIV followed by the ciphertext
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] aad) {
        checkNonce(nonce);
        byte[] siv = s2v(k1, new byte[][]{orEmpty(aad), nonce}, plaintext);
        byte[] ct = ctr(k2, siv, plaintext);
        byte[] out = new byte[siv.length + ct.length];
        System.arraycopy(siv, 0, out, 0, siv.length);
        System.arraycopy(ct, 0, out, siv.length, ct.length);
        return out;
    }

    /**
     * Decrypts {@code ciphertext} (SIV followed by ciphertext), verifying the
     * SIV against the recomputed value.
     *
     * @param ciphertext the SIV followed by the ciphertext
     * @param nonce      the 16-byte nonce used during encryption
     * @param aad        additional authenticated data, or {@code null}
     * @return the decrypted plaintext
     * @throws AEADBadTagException on authentication failure
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        checkNonce(nonce);
        if (ciphertext.length < Constants.AES_BLOCK_SIZE) {
            throw new AEADBadTagException("AES-SIV ciphertext is too short");
        }
        byte[] siv = Arrays.copyOfRange(ciphertext, 0, Constants.AES_BLOCK_SIZE);
        byte[] ct = Arrays.copyOfRange(ciphertext, Constants.AES_BLOCK_SIZE, ciphertext.length);
        byte[] plaintext = ctr(k2, siv, ct);
        byte[] expected = s2v(k1, new byte[][]{orEmpty(aad), nonce}, plaintext);
        if (!MessageDigest.isEqual(expected, siv)) {
            throw new AEADBadTagException("AES-SIV authentication failed");
        }
        return plaintext;
    }

    /**
     * Returns {@code data} or an empty array if it is {@code null}.
     *
     * @param data the data, or {@code null}
     * @return {@code data} or an empty array
     */
    private static byte[] orEmpty(byte[] data) {
        return data == null ? new byte[0] : data;
    }

    /**
     * Validates that {@code nonce} is 16 bytes long.
     *
     * @param nonce the nonce to validate
     */
    private static void checkNonce(byte[] nonce) {
        if (nonce.length != Constants.AES_BLOCK_SIZE) {
            throw new IllegalArgumentException("AES-SIV nonce must be "
                    + Constants.AES_BLOCK_SIZE + " bytes");
        }
    }

    /**
     * S2V: string-to-vector of RFC 5297, computed over {@code ad} followed by
     * the last string {@code last}.
     *
     * @param k1   the S2V sub-key (32 bytes)
     * @param ad   the associated-data strings
     * @param last the final string (typically the plaintext)
     * @return the 16-byte synthetic IV
     */
    static byte[] s2v(byte[] k1, byte[][] ad, byte[] last) {
        byte[] d = cmac(k1, new byte[Constants.AES_BLOCK_SIZE]);
        for (byte[] s : ad) {
            byte[] dd = dbl(d);
            byte[] c = cmac(k1, s);
            for (int i = 0; i < d.length; i++) {
                d[i] = (byte) (dd[i] ^ c[i]);
            }
        }

        byte[] t;
        if (last.length >= Constants.AES_BLOCK_SIZE) {
            t = last.clone();
            int off = t.length - Constants.AES_BLOCK_SIZE;
            for (int i = 0; i < Constants.AES_BLOCK_SIZE; i++) {
                t[off + i] ^= d[i];
            }
        } else {
            t = new byte[Constants.AES_BLOCK_SIZE];
            System.arraycopy(last, 0, t, 0, last.length);
            t[last.length] = (byte) 0x80;
            byte[] dd = dbl(d);
            for (int i = 0; i < t.length; i++) {
                t[i] ^= dd[i];
            }
        }
        return cmac(k1, t);
    }

    /**
     * CTR: AES-CTR with the SIV (bits 31 and 63 cleared) as initial counter.
     *
     * @param k2   the CTR sub-key (32 bytes)
     * @param siv  the 16-byte synthetic IV
     * @param data the data to encrypt or decrypt
     * @return the encrypted/decrypted data
     */
    static byte[] ctr(byte[] k2, byte[] siv, byte[] data) {
        byte[] q = siv.clone();
        q[8] &= 0x7f;
        q[12] &= 0x7f;
        SICBlockCipher cipher = new SICBlockCipher(new AESEngine());
        cipher.init(true, new ParametersWithIV(new KeyParameter(k2), q));
        byte[] out = new byte[data.length];
        cipher.processBytes(data, 0, data.length, out, 0);
        return out;
    }

    /**
     * Computes AES-CMAC (RFC 4493) of {@code data} under {@code key}.
     *
     * @param key  the CMAC key (16 or 32 bytes)
     * @param data the data to authenticate
     * @return the 16-byte CMAC
     */
    private static byte[] cmac(byte[] key, byte[] data) {
        CMac mac = new CMac(new AESEngine());
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        byte[] out = new byte[Constants.AES_BLOCK_SIZE];
        mac.doFinal(out, 0);
        return out;
    }

    /**
     * RFC 4493 doubling: left shift, conditional XOR with {@code 0x87}.
     *
     * @param x the 16-byte block to double
     * @return the doubled block
     */
    private static byte[] dbl(byte[] x) {
        byte[] out = new byte[Constants.AES_BLOCK_SIZE];
        byte carry = 0;
        for (int i = out.length - 1; i >= 0; i--) {
            out[i] = (byte) ((x[i] << 1) | carry);
            carry = (byte) ((x[i] & 0x80) >>> 7);
        }
        if ((x[0] & 0x80) != 0) {
            out[out.length - 1] ^= 0x87;
        }
        return out;
    }
}
