package de.sfuhrm.gocryptfs4j.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * AES-256-GCM helper matching Go's {@code cipher.NewGCMWithNonceSize} with a
 * 16-byte tag and a caller-supplied nonce length.
 *
 * <p>gocryptfs uses 128-bit IVs for file content and (for filesystems created
 * by gocryptfs &ge; v1.3) 128-bit IVs for the master key; pre-v1.3 config files
 * use 96-bit IVs. Both are supported by passing the nonce explicitly.</p>
 */
public final class Gcm {

    private final SecretKeySpec key;

    public Gcm(byte[] key) {
        if (key.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("GCM key must be " + Constants.KEY_LEN + " bytes");
        }
        this.key = new SecretKeySpec(key, "AES");
    }

    /** Encrypts {@code plaintext}, returning ciphertext || 16-byte tag. */
    public byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(Constants.AUTH_TAG_LEN * 8, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypts {@code ciphertext} (which must include the 16-byte tag), verifying
     * the tag and {@code aad}.
     *
     * @throws javax.crypto.AEADBadTagException (a GeneralSecurityException) on
     *         authentication failure.
     */
    public byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(Constants.AUTH_TAG_LEN * 8, nonce));
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(ciphertext);
    }
}
