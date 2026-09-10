package de.sfuhrm.gocryptfs4j.crypto;

import java.security.GeneralSecurityException;

/**
 * Minimal authenticated-encryption abstraction used for file content and the
 * master key. The supported backends (AES-256-GCM, XChaCha20-Poly1305 and
 * AES-SIV) append a 16-byte authentication tag (or SIV) to the ciphertext and
 * authenticate the additional data.
 */
public interface ContentCipher {

    /**
     * Encrypts {@code plaintext}, returning ciphertext followed by a 16-byte
     * authentication tag.
     *
     * @param plaintext the plaintext to encrypt
     * @param nonce     the nonce (length depends on the cipher)
     * @param aad       additional authenticated data, or {@code null}
     * @return the ciphertext followed by the 16-byte tag
     */
    byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] aad);

    /**
     * Decrypts {@code ciphertext} (which must include the trailing 16-byte
     * tag), verifying the tag and {@code aad}.
     *
     * @param ciphertext the ciphertext including the 16-byte tag
     * @param nonce      the nonce used during encryption
     * @param aad        additional authenticated data, or {@code null}
     * @return the decrypted plaintext
     * @throws GeneralSecurityException on authentication failure
     */
    byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] aad) throws GeneralSecurityException;
}
