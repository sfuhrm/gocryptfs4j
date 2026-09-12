package de.sfuhrm.gocryptfs4j.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Minimal authenticated-encryption abstraction used for file content and the
 * master key. The supported backends (AES-256-GCM, XChaCha20-Poly1305 and
 * AES-SIV) append a 16-byte authentication tag (or SIV) to the ciphertext and
 * authenticate the additional data.
 *
 * <p>The offset-based {@link #encrypt(byte[], int, int, byte[], byte[], int, int, byte[], int)}
 * and {@link #decrypt(byte[], int, int, byte[], byte[], int, int, byte[], int)}
 * methods let callers encrypt and decrypt directly into a shared output buffer
 * without allocating per operation.</p>
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

    /**
     * Encrypts {@code inLen} bytes from {@code in} and writes the ciphertext
     * followed by the 16-byte tag to {@code out} at {@code outOff}, without
     * allocating a result array.
     *
     * <p>The default implementation allocates temporary buffers; the built-in
     * ciphers override it.</p>
     *
     * @param in     the input buffer
     * @param inOff  the input offset
     * @param inLen  the input length in bytes
     * @param nonce  the nonce (length depends on the cipher)
     * @param aad    the additional authenticated data buffer, or {@code null}
     * @param aadOff the additional-data offset
     * @param aadLen the additional-data length in bytes
     * @param out    the output buffer
     * @param outOff the output offset
     * @return the number of bytes written to {@code out}
     */
    default int encrypt(byte[] in, int inOff, int inLen, byte[] nonce,
                        byte[] aad, int aadOff, int aadLen, byte[] out, int outOff) {
        byte[] sliceIn = Arrays.copyOfRange(in, inOff, inOff + inLen);
        byte[] sliceAad = (aad == null || aadLen == 0) ? null
                : Arrays.copyOfRange(aad, aadOff, aadOff + aadLen);
        byte[] encrypted = encrypt(sliceIn, nonce, sliceAad);
        System.arraycopy(encrypted, 0, out, outOff, encrypted.length);
        return encrypted.length;
    }

    /**
     * Decrypts {@code inLen} bytes from {@code in} (including the trailing
     * 16-byte tag) and writes the plaintext to {@code out} at {@code outOff},
     * without allocating a result array.
     *
     * <p>The default implementation allocates temporary buffers; the built-in
     * ciphers override it.</p>
     *
     * @param in     the ciphertext buffer including the tag
     * @param inOff  the input offset
     * @param inLen  the input length in bytes
     * @param nonce  the nonce used during encryption
     * @param aad    the additional authenticated data buffer, or {@code null}
     * @param aadOff the additional-data offset
     * @param aadLen the additional-data length in bytes
     * @param out    the output buffer
     * @param outOff the output offset
     * @return the number of plaintext bytes written to {@code out}
     * @throws GeneralSecurityException on authentication failure
     */
    default int decrypt(byte[] in, int inOff, int inLen, byte[] nonce,
                        byte[] aad, int aadOff, int aadLen, byte[] out, int outOff)
            throws GeneralSecurityException {
        byte[] sliceIn = Arrays.copyOfRange(in, inOff, inOff + inLen);
        byte[] sliceAad = (aad == null || aadLen == 0) ? null
                : Arrays.copyOfRange(aad, aadOff, aadOff + aadLen);
        byte[] plain = decrypt(sliceIn, nonce, sliceAad);
        System.arraycopy(plain, 0, out, outOff, plain.length);
        return plain.length;
    }

    /**
     * Wipes any key material held by this cipher. Implementations that hold no
     * copy of the key may leave this as a no-op.
     */
    default void wipe() {
    }
}
