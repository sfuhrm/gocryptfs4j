package de.sfuhrm.gocryptfs4j.crypto;

/**
 * Keyless geometry of the content-encryption block format: plaintext and
 * ciphertext block sizes, nonce length, and the translations between plaintext
 * and ciphertext offsets and sizes.
 *
 * <p>These values and computations depend only on the configured nonce length
 * and plaintext block size, never on any key material, so metadata and listing
 * code can translate sizes and offsets without holding or deriving a key.</p>
 */
public final class ContentGeometry {

    /** Plaintext block size. */
    public final long plainBS;
    /** Ciphertext block size (plainBS + ivLen + tag). */
    public final long cipherBS;
    /** Nonce length in bytes. */
    public final int ivLen;

    /**
     * Creates the geometry for a content cipher.
     *
     * @param ivLen   the nonce length in bytes
     * @param plainBS the plaintext block size in bytes
     * @throws IllegalArgumentException if {@code ivLen} or {@code plainBS} is not positive
     */
    public ContentGeometry(int ivLen, long plainBS) {
        if (ivLen <= 0) {
            throw new IllegalArgumentException("ivLen must be positive: " + ivLen);
        }
        if (plainBS <= 0) {
            throw new IllegalArgumentException("plainBS must be positive: " + plainBS);
        }
        this.ivLen = ivLen;
        this.plainBS = plainBS;
        this.cipherBS = plainBS + ivLen + Constants.AUTH_TAG_LEN;
    }

    /**
     * Returns the per-block overhead (nonce + tag) in bytes.
     *
     * @return the ciphertext minus plaintext block size
     */
    public long blockOverhead() {
        return cipherBS - plainBS;
    }

    /**
     * Converts a plaintext offset to the block number it resides in.
     *
     * @param plainOffset the plaintext offset in bytes
     * @return the block number
     */
    public long plainOffToBlockNo(long plainOffset) {
        return plainOffset / plainBS;
    }

    /**
     * Converts a ciphertext offset to the block number it resides in.
     *
     * @param cipherOffset the ciphertext offset in bytes (past the file header)
     * @return the block number
     * @throws IllegalArgumentException if the offset lies inside the file header
     */
    public long cipherOffToBlockNo(long cipherOffset) {
        if (cipherOffset < Constants.HEADER_LEN) {
            throw new IllegalArgumentException("offset inside file header");
        }
        return (cipherOffset - Constants.HEADER_LEN) / cipherBS;
    }

    /**
     * Returns the ciphertext offset of the given block.
     *
     * @param blockNo the block number
     * @return the ciphertext offset in bytes
     */
    public long blockNoToCipherOff(long blockNo) {
        return Constants.HEADER_LEN + blockNo * cipherBS;
    }

    /**
     * Returns the plaintext offset of the given block.
     *
     * @param blockNo the block number
     * @return the plaintext offset in bytes
     */
    public long blockNoToPlainOff(long blockNo) {
        return blockNo * plainBS;
    }

    /**
     * Converts a ciphertext file size to the plaintext size.
     *
     * @param cipherSize the ciphertext file size in bytes
     * @return the plaintext size in bytes
     */
    public long cipherSizeToPlainSize(long cipherSize) {
        if (cipherSize == 0) {
            return 0;
        }
        if (cipherSize == Constants.HEADER_LEN) {
            return 0;
        }
        if (cipherSize < Constants.HEADER_LEN) {
            return 0;
        }
        long lastBlockSize = (cipherSize - Constants.HEADER_LEN) % cipherBS;
        if (lastBlockSize > 0 && lastBlockSize <= blockOverhead()) {
            cipherSize = cipherSize - lastBlockSize + blockOverhead() + 1;
        }
        long blockNo = cipherOffToBlockNo(cipherSize - 1);
        long blockCount = blockNo + 1;
        long overhead = blockOverhead() * blockCount + Constants.HEADER_LEN;
        if (overhead > cipherSize) {
            return 0;
        }
        return cipherSize - overhead;
    }

    /**
     * Converts a plaintext size to the corresponding ciphertext size.
     *
     * @param plainSize the plaintext size in bytes
     * @return the ciphertext size in bytes
     */
    public long plainSizeToCipherSize(long plainSize) {
        if (plainSize == 0) {
            return 0;
        }
        return plainOffToCipherOff(plainSize - 1) + 1;
    }

    /**
     * Returns the highest ciphertext offset touched when reading/writing at
     * {@code plainOff}.
     *
     * @param plainOff the plaintext offset in bytes
     * @return the highest ciphertext offset in bytes
     */
    public long plainOffToCipherOff(long plainOff) {
        long startOfBlock = blockNoToCipherOff(plainOffToBlockNo(plainOff));
        return startOfBlock + plainOff % plainBS + blockOverhead();
    }
}
