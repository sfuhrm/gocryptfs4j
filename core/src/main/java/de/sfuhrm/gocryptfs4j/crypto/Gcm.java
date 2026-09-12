package de.sfuhrm.gocryptfs4j.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/**
 * AES-256-GCM helper matching Go's {@code cipher.NewGCMWithNonceSize} with a
 * 16-byte tag and a caller-supplied nonce length.
 *
 * <p>gocryptfs uses 128-bit IVs for file content and (for filesystems created
 * by gocryptfs &ge; v1.3) 128-bit IVs for the master key; pre-v1.3 config files
 * use 96-bit IVs. Both are supported by passing the nonce explicitly.</p>
 */
public final class Gcm implements ContentCipher {

    private final byte[] key;

    private final ThreadLocal<Cipher> encryptCipher = ThreadLocal.withInitial(Gcm::newCipher);
    private final ThreadLocal<Cipher> decryptCipher = ThreadLocal.withInitial(Gcm::newCipher);

    private static Cipher newCipher() {
        try {
            return Cipher.getInstance("AES/GCM/NoPadding");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM unavailable", e);
        }
    }

    /**
     * Creates an AES-256-GCM instance.
     *
     * @param key the 32-byte AES key
     * @throws NullPointerException if {@code key} is {@code null}
     * @throws IllegalArgumentException if {@code key} is not 32 bytes long
     */
    public Gcm(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("GCM key must be " + Constants.KEY_LEN + " bytes");
        }
        this.key = Arrays.copyOf(key, key.length);
    }

    @Override
    public void wipe() {
        Arrays.fill(key, (byte) 0);
    }

    /**
     * Encrypts {@code plaintext}, returning ciphertext followed by a 16-byte tag.
     *
     * @param plaintext the plaintext to encrypt
     * @param nonce     the nonce (12 or 16 bytes)
     * @param aad       additional authenticated data, or {@code null}
     * @return the ciphertext followed by the 16-byte tag
     * @throws NullPointerException if {@code plaintext} or {@code nonce} is {@code null}
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] aad) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(nonce, "nonce");
        try {
            Cipher cipher = encryptCipher.get();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(Constants.AUTH_TAG_LEN * 8, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypts {@code ciphertext} (which must include the trailing 16-byte tag),
     * verifying the tag and {@code aad}.
     *
     * @param ciphertext the ciphertext including the 16-byte tag
     * @param nonce      the nonce used during encryption
     * @param aad        additional authenticated data, or {@code null}
     * @return the decrypted plaintext
     * @throws javax.crypto.AEADBadTagException (a GeneralSecurityException) on
     *         authentication failure
     * @throws NullPointerException if {@code ciphertext} or {@code nonce} is {@code null}
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(nonce, "nonce");
        Cipher cipher = decryptCipher.get();
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(Constants.AUTH_TAG_LEN * 8, nonce));
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(ciphertext);
    }

    @Override
    public int encrypt(byte[] in, int inOff, int inLen, byte[] nonce,
                       byte[] aad, int aadOff, int aadLen, byte[] out, int outOff) {
        try {
            Cipher cipher = encryptCipher.get();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(Constants.AUTH_TAG_LEN * 8, nonce));
            if (aadLen > 0) {
                cipher.updateAAD(aad, aadOff, aadLen);
            }
            return cipher.doFinal(in, inOff, inLen, out, outOff);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    @Override
    public int decrypt(byte[] in, int inOff, int inLen, byte[] nonce,
                       byte[] aad, int aadOff, int aadLen, byte[] out, int outOff)
            throws GeneralSecurityException {
        Cipher cipher = decryptCipher.get();
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(Constants.AUTH_TAG_LEN * 8, nonce));
        if (aadLen > 0) {
            cipher.updateAAD(aad, aadOff, aadLen);
        }
        return cipher.doFinal(in, inOff, inLen, out, outOff);
    }
}
