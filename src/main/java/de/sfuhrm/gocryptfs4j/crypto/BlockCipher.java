package de.sfuhrm.gocryptfs4j.crypto;

/**
 * Minimal abstraction over a 128-bit block cipher, as needed by EME.
 */
public interface BlockCipher {

    /** Block size in bytes (must be 16). */
    int blockSize();

    /** Encrypts one block. */
    void encrypt(byte[] in, int inOff, byte[] out, int outOff);

    /** Decrypts one block. */
    void decrypt(byte[] in, int inOff, byte[] out, int outOff);
}
