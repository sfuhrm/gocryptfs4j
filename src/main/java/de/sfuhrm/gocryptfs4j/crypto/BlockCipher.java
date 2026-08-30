package de.sfuhrm.gocryptfs4j.crypto;

/**
 * Minimal abstraction over a 128-bit block cipher, as needed by EME.
 */
public interface BlockCipher {

    /**
     * Returns the block size in bytes.
     *
     * @return the block size in bytes (must be 16)
     */
    int blockSize();

    /**
     * Encrypts one block.
     *
     * @param in     the input block
     * @param inOff  the offset into {@code in}
     * @param out    the output buffer
     * @param outOff the offset into {@code out}
     */
    void encrypt(byte[] in, int inOff, byte[] out, int outOff);

    /**
     * Decrypts one block.
     *
     * @param in     the input block
     * @param inOff  the offset into {@code in}
     * @param out    the output buffer
     * @param outOff the offset into {@code out}
     */
    void decrypt(byte[] in, int inOff, byte[] out, int outOff);
}
