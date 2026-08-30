package de.sfuhrm.gocryptfs4j.crypto;

import java.security.GeneralSecurityException;

/**
 * Minimal authenticated-encryption abstraction used for file content and the
 * master key. Both supported backends (AES-256-GCM and XChaCha20-Poly1305)
 * append a 16-byte tag to the ciphertext and authenticate the additional data.
 */
public interface ContentCipher {

    /** Encrypts {@code plaintext}, returning ciphertext || 16-byte tag. */
    byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] aad);

    /**
     * Decrypts {@code ciphertext} (including the 16-byte tag), verifying the
     * tag and {@code aad}.
     *
     * @throws GeneralSecurityException on authentication failure.
     */
    byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] aad) throws GeneralSecurityException;
}
