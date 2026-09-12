package de.sfuhrm.gocryptfs4j.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Encrypts and decrypts file content blocks.
 *
 * <p>File content is split into 4096-byte plaintext blocks. Each block is
 * encrypted with AES-256-GCM using a fresh random nonce; the 8-byte big-endian
 * block number and the 16-byte file id are used as additional authenticated
 * data. A block is stored as {@code nonce || ciphertext || tag}.</p>
 *
 * <p>The bulk methods {@link #encryptBlocks(byte[], int, int, long, byte[], byte[], int)}
 * and {@link #decryptBlocks(byte[], int, int, long, byte[], byte[], int)} operate
 * on a caller-supplied output buffer and reuse per-thread scratch buffers, so
 * contiguous multi-block reads and writes allocate nothing per block.</p>
 */
public final class ContentEnc {

    /** Plaintext block size. */
    public final long plainBS;
    /** Ciphertext block size (plainBS + ivLen + tag). */
    public final long cipherBS;
    /** Nonce length in bytes. */
    public final int ivLen;

    private final ContentCipher cipher;
    private final ThreadLocal<byte[]> aadBuffer;
    private final ThreadLocal<byte[]> nonceBuffer;

    /**
     * Creates a content-encryption helper using AES-256-GCM with the default
     * plaintext block size.
     *
     * @param gcmKey the 32-byte AES key
     * @param ivLen  the nonce length in bytes
     */
    public ContentEnc(byte[] gcmKey, int ivLen) {
        this(new Gcm(gcmKey), ivLen, Constants.DEFAULT_PLAIN_BS);
    }

    /**
     * Creates a content-encryption helper using AES-256-GCM.
     *
     * @param gcmKey  the 32-byte AES key
     * @param ivLen   the nonce length in bytes
     * @param plainBS the plaintext block size in bytes
     */
    public ContentEnc(byte[] gcmKey, int ivLen, long plainBS) {
        this(new Gcm(gcmKey), ivLen, plainBS);
    }

    /**
     * Creates a content-encryption helper with the default plaintext block size.
     *
     * @param cipher the authenticated-encryption cipher
     * @param ivLen  the nonce length in bytes
     */
    public ContentEnc(ContentCipher cipher, int ivLen) {
        this(cipher, ivLen, Constants.DEFAULT_PLAIN_BS);
    }

    /**
     * Creates a content-encryption helper.
     *
     * @param cipher  the authenticated-encryption cipher
     * @param ivLen   the nonce length in bytes
     * @param plainBS the plaintext block size in bytes
     * @throws NullPointerException if {@code cipher} is {@code null}
     * @throws IllegalArgumentException if {@code ivLen} or {@code plainBS} is not positive
     */
    public ContentEnc(ContentCipher cipher, int ivLen, long plainBS) {
        this.cipher = Objects.requireNonNull(cipher, "cipher");
        if (ivLen <= 0) {
            throw new IllegalArgumentException("ivLen must be positive: " + ivLen);
        }
        if (plainBS <= 0) {
            throw new IllegalArgumentException("plainBS must be positive: " + plainBS);
        }
        this.ivLen = ivLen;
        this.plainBS = plainBS;
        this.cipherBS = plainBS + ivLen + Constants.AUTH_TAG_LEN;
        this.aadBuffer = ThreadLocal.withInitial(() -> new byte[8 + Constants.HEADER_ID_LEN]);
        this.nonceBuffer = ThreadLocal.withInitial(() -> new byte[ivLen]);
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
     * Wipes the underlying cipher's key material.
     */
    public void wipe() {
        cipher.wipe();
    }

    private static byte[] concatAD(long blockNo, byte[] fileId) {
        byte[] aad = new byte[8 + (fileId == null ? 0 : fileId.length)];
        fillAad(blockNo, fileId, aad);
        return aad;
    }

    /**
     * Writes the additional authenticated data (8-byte big-endian block number,
     * optionally followed by the file id) into {@code aad}.
     *
     * @return the number of bytes written
     */
    private static int fillAad(long blockNo, byte[] fileId, byte[] aad) {
        for (int i = 0; i < 8; i++) {
            aad[7 - i] = (byte) (blockNo >>> (i * 8));
        }
        if (fileId != null && fileId.length > 0) {
            System.arraycopy(fileId, 0, aad, 8, fileId.length);
            return 8 + fileId.length;
        }
        return 8;
    }

    /**
     * Encrypts one block with a fresh random nonce.
     *
     * @param plaintext the plaintext block
     * @param blockNo   the block number (used as additional authenticated data)
     * @param fileId    the 16-byte file id, or {@code null}
     * @return the nonce followed by ciphertext and tag
     * @throws NullPointerException if {@code plaintext} is {@code null}
     * @throws IllegalArgumentException if {@code blockNo} is negative
     */
    public byte[] encryptBlock(byte[] plaintext, long blockNo, byte[] fileId) {
        Objects.requireNonNull(plaintext, "plaintext");
        if (blockNo < 0) {
            throw new IllegalArgumentException("negative block number: " + blockNo);
        }
        if (plaintext.length == 0) {
            return plaintext;
        }
        return encryptBlock(plaintext, blockNo, fileId, Keys.randomBytes(ivLen));
    }

    /**
     * Encrypts one block with a caller-supplied nonce.
     *
     * @param plaintext the plaintext block
     * @param blockNo   the block number (used as additional authenticated data)
     * @param fileId    the 16-byte file id, or {@code null}
     * @param nonce     the nonce to use
     * @return the nonce followed by ciphertext and tag
     * @throws NullPointerException if {@code plaintext} or {@code nonce} is {@code null}
     * @throws IllegalArgumentException if {@code blockNo} is negative or {@code nonce} has the wrong length
     */
    public byte[] encryptBlock(byte[] plaintext, long blockNo, byte[] fileId, byte[] nonce) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(nonce, "nonce");
        if (blockNo < 0) {
            throw new IllegalArgumentException("negative block number: " + blockNo);
        }
        if (plaintext.length == 0) {
            return plaintext;
        }
        if (nonce.length != ivLen) {
            throw new IllegalArgumentException("wrong nonce length");
        }
        byte[] aad = concatAD(blockNo, fileId);
        byte[] out = new byte[nonce.length + plaintext.length + Constants.AUTH_TAG_LEN];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        cipher.encrypt(plaintext, 0, plaintext.length, nonce, aad, 0, aad.length, out, nonce.length);
        return out;
    }

    /**
     * Encrypts a sequence of plaintext blocks starting at {@code firstBlockNo}
     * into {@code out}, without allocating per block.
     *
     * <p>The plaintext is stored contiguously in
     * {@code plain[plainOff, plainOff + plainLen)} and is split into
     * {@link #plainBS}-sized blocks; only the last block may be shorter. Each
     * block is prefixed with a fresh random nonce exactly like
     * {@link #encryptBlock(byte[], long, byte[])}.</p>
     *
     * @param plain        the plaintext buffer
     * @param plainOff     the plaintext offset
     * @param plainLen     the plaintext length in bytes
     * @param firstBlockNo the block number of the first block
     * @param fileId       the 16-byte file id, or {@code null}
     * @param out          the output buffer
     * @param outOff       the output offset
     * @return the number of ciphertext bytes written to {@code out}
     * @throws NullPointerException if {@code plain} or {@code out} is {@code null}
     * @throws IllegalArgumentException if {@code plainLen} or {@code firstBlockNo} is negative
     */
    public int encryptBlocks(byte[] plain, int plainOff, int plainLen, long firstBlockNo,
                             byte[] fileId, byte[] out, int outOff) {
        Objects.requireNonNull(plain, "plain");
        Objects.requireNonNull(out, "out");
        if (plainLen < 0) {
            throw new IllegalArgumentException("negative plaintext length: " + plainLen);
        }
        if (firstBlockNo < 0) {
            throw new IllegalArgumentException("negative block number: " + firstBlockNo);
        }
        byte[] aad = aadBuffer.get();
        byte[] nonce = nonceBuffer.get();
        int pos = plainOff;
        int remaining = plainLen;
        int outPos = outOff;
        long blockNo = firstBlockNo;
        while (remaining > 0) {
            int blockLen = (int) Math.min(plainBS, remaining);
            Keys.randomBytes(nonce);
            int aadLen = fillAad(blockNo, fileId, aad);
            System.arraycopy(nonce, 0, out, outPos, ivLen);
            outPos += ivLen;
            outPos += cipher.encrypt(plain, pos, blockLen, nonce, aad, 0, aadLen, out, outPos);
            pos += blockLen;
            remaining -= blockLen;
            blockNo++;
        }
        return outPos - outOff;
    }

    /**
     * Verifies and decrypts one block. All-zero ciphertext blocks (sparse file
     * holes) are passed through unchanged as all-zero plaintext.
     *
     * @param ciphertext the ciphertext block (nonce, ciphertext and tag)
     * @param blockNo    the block number (used as additional authenticated data)
     * @param fileId     the 16-byte file id, or {@code null}
     * @return the decrypted plaintext
     * @throws GeneralSecurityException on authentication failure
     * @throws NullPointerException if {@code ciphertext} is {@code null}
     * @throws IllegalArgumentException if {@code blockNo} is negative or the block is malformed
     */
    public byte[] decryptBlock(byte[] ciphertext, long blockNo, byte[] fileId) throws GeneralSecurityException {
        Objects.requireNonNull(ciphertext, "ciphertext");
        if (blockNo < 0) {
            throw new IllegalArgumentException("negative block number: " + blockNo);
        }
        if (ciphertext.length == 0) {
            return ciphertext;
        }
        if (ciphertext.length == cipherBS && isAllZero(ciphertext)) {
            return new byte[(int) plainBS];
        }
        if (ciphertext.length < ivLen) {
            throw new IllegalArgumentException("block is too short");
        }
        byte[] nonce = new byte[ivLen];
        System.arraycopy(ciphertext, 0, nonce, 0, ivLen);
        if (isAllZero(nonce)) {
            throw new IllegalArgumentException("all-zero nonce");
        }
        byte[] aad = concatAD(blockNo, fileId);
        int inLen = ciphertext.length - ivLen;
        byte[] out = new byte[Math.max(inLen - Constants.AUTH_TAG_LEN, 0)];
        cipher.decrypt(ciphertext, ivLen, inLen, nonce, aad, 0, aad.length, out, 0);
        return out;
    }

    /**
     * Decrypts a sequence of blocks starting at {@code firstBlockNo}.
     *
     * @param ciphertext   the ciphertext to decrypt
     * @param firstBlockNo the block number of the first block
     * @param fileId       the 16-byte file id, or {@code null}
     * @return the decrypted plaintext
     * @throws GeneralSecurityException on authentication failure
     * @throws NullPointerException if {@code ciphertext} is {@code null}
     * @throws IllegalArgumentException if {@code firstBlockNo} is negative
     */
    public byte[] decryptBlocks(byte[] ciphertext, long firstBlockNo, byte[] fileId) throws GeneralSecurityException {
        Objects.requireNonNull(ciphertext, "ciphertext");
        if (firstBlockNo < 0) {
            throw new IllegalArgumentException("negative block number: " + firstBlockNo);
        }
        if (ciphertext.length == 0) {
            return ciphertext;
        }
        int blockCount = (int) ((ciphertext.length + cipherBS - 1) / cipherBS);
        byte[] out = new byte[blockCount * (int) plainBS];
        int n = decryptBlocks(ciphertext, 0, ciphertext.length, firstBlockNo, fileId, out, 0);
        return Arrays.copyOf(out, n);
    }

    /**
     * Decrypts a sequence of blocks starting at {@code firstBlockNo} into
     * {@code out}, without allocating per block.
     *
     * <p>The ciphertext is stored contiguously in
     * {@code cipher[cipherOff, cipherOff + cipherLen)} and is split into
     * {@link #cipherBS}-sized blocks, except possibly the last one. All-zero
     * full blocks are treated as sparse holes and decrypted to zero
     * plaintext.</p>
     *
     * @param cipherBuf    the ciphertext buffer
     * @param cipherOff    the ciphertext offset
     * @param cipherLen    the ciphertext length in bytes
     * @param firstBlockNo the block number of the first block
     * @param fileId       the 16-byte file id, or {@code null}
     * @param out          the output buffer
     * @param outOff       the output offset
     * @return the number of plaintext bytes written to {@code out}
     * @throws GeneralSecurityException on authentication failure
     * @throws NullPointerException if {@code cipherBuf} or {@code out} is {@code null}
     * @throws IllegalArgumentException if {@code cipherLen} or {@code firstBlockNo} is negative or a block is malformed
     */
    public int decryptBlocks(byte[] cipherBuf, int cipherOff, int cipherLen, long firstBlockNo,
                             byte[] fileId, byte[] out, int outOff) throws GeneralSecurityException {
        Objects.requireNonNull(cipherBuf, "cipherBuf");
        Objects.requireNonNull(out, "out");
        if (cipherLen < 0) {
            throw new IllegalArgumentException("negative ciphertext length: " + cipherLen);
        }
        if (firstBlockNo < 0) {
            throw new IllegalArgumentException("negative block number: " + firstBlockNo);
        }
        byte[] aad = aadBuffer.get();
        byte[] nonce = nonceBuffer.get();
        int pos = cipherOff;
        int remaining = cipherLen;
        int outPos = outOff;
        long blockNo = firstBlockNo;
        while (remaining > 0) {
            int blockLen = (int) Math.min(cipherBS, remaining);
            if (blockLen == cipherBS && isAllZero(cipherBuf, pos, blockLen)) {
                int zeroLen = (int) plainBS;
                Arrays.fill(out, outPos, outPos + zeroLen, (byte) 0);
                outPos += zeroLen;
            } else {
                if (blockLen < ivLen) {
                    throw new IllegalArgumentException("block is too short");
                }
                if (isAllZero(cipherBuf, pos, ivLen)) {
                    throw new IllegalArgumentException("all-zero nonce");
                }
                System.arraycopy(cipherBuf, pos, nonce, 0, ivLen);
                int aadLen = fillAad(blockNo, fileId, aad);
                outPos += cipher.decrypt(cipherBuf, pos + ivLen, blockLen - ivLen, nonce,
                        aad, 0, aadLen, out, outPos);
            }
            pos += blockLen;
            remaining -= blockLen;
            blockNo++;
        }
        return outPos - outOff;
    }

    private static boolean isAllZero(byte[] b) {
        return isAllZero(b, 0, b.length);
    }

    private static boolean isAllZero(byte[] b, int off, int len) {
        for (int i = 0; i < len; i++) {
            if (b[off + i] != 0) {
                return false;
            }
        }
        return true;
    }

    // ---- Size translations ----

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
