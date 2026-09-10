package de.sfuhrm.gocryptfs4j.crypto;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;

/**
 * Encrypts and decrypts file content blocks.
 *
 * <p>File content is split into 4096-byte plaintext blocks. Each block is
 * encrypted with AES-256-GCM using a fresh random nonce; the 8-byte big-endian
 * block number and the 16-byte file id are used as additional authenticated
 * data. A block is stored as {@code nonce || ciphertext || tag}.</p>
 */
public final class ContentEnc {

    /** Plaintext block size. */
    public final long plainBS;
    /** Ciphertext block size (plainBS + ivLen + tag). */
    public final long cipherBS;
    /** Nonce length in bytes. */
    public final int ivLen;

    private final ContentCipher cipher;
    private final byte[] allZeroBlock;

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
     */
    public ContentEnc(ContentCipher cipher, int ivLen, long plainBS) {
        this.ivLen = ivLen;
        this.plainBS = plainBS;
        this.cipherBS = plainBS + ivLen + Constants.AUTH_TAG_LEN;
        this.cipher = cipher;
        this.allZeroBlock = new byte[(int) cipherBS];
    }

    /**
     * Returns the per-block overhead (nonce + tag) in bytes.
     *
     * @return the ciphertext minus plaintext block size
     */
    public long blockOverhead() {
        return cipherBS - plainBS;
    }

    private static byte[] concatAD(long blockNo, byte[] fileId) {
        byte[] aad = new byte[8 + (fileId == null ? 0 : fileId.length)];
        for (int i = 0; i < 8; i++) {
            aad[7 - i] = (byte) (blockNo >>> (i * 8));
        }
        if (fileId != null) {
            System.arraycopy(fileId, 0, aad, 8, fileId.length);
        }
        return aad;
    }

    /**
     * Encrypts one block with a fresh random nonce.
     *
     * @param plaintext the plaintext block
     * @param blockNo   the block number (used as additional authenticated data)
     * @param fileId    the 16-byte file id, or {@code null}
     * @return the nonce followed by ciphertext and tag
     */
    public byte[] encryptBlock(byte[] plaintext, long blockNo, byte[] fileId) {
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
     */
    public byte[] encryptBlock(byte[] plaintext, long blockNo, byte[] fileId, byte[] nonce) {
        if (plaintext.length == 0) {
            return plaintext;
        }
        if (nonce.length != ivLen) {
            throw new IllegalArgumentException("wrong nonce length");
        }
        byte[] aad = concatAD(blockNo, fileId);
        byte[] ct = cipher.encrypt(plaintext, nonce, aad);
        byte[] out = new byte[nonce.length + ct.length];
        System.arraycopy(nonce, 0, out, 0, nonce.length);
        System.arraycopy(ct, 0, out, nonce.length, ct.length);
        return out;
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
     */
    public byte[] decryptBlock(byte[] ciphertext, long blockNo, byte[] fileId) throws GeneralSecurityException {
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
        byte[] ct = new byte[ciphertext.length - ivLen];
        System.arraycopy(ciphertext, ivLen, ct, 0, ct.length);
        byte[] aad = concatAD(blockNo, fileId);
        return cipher.decrypt(ct, nonce, aad);
    }

    /**
     * Decrypts a sequence of blocks starting at {@code firstBlockNo}.
     *
     * @param ciphertext   the ciphertext to decrypt
     * @param firstBlockNo the block number of the first block
     * @param fileId       the 16-byte file id, or {@code null}
     * @return the decrypted plaintext
     * @throws GeneralSecurityException on authentication failure
     */
    public byte[] decryptBlocks(byte[] ciphertext, long firstBlockNo, byte[] fileId) throws GeneralSecurityException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(ciphertext.length);
        int pos = 0;
        long blockNo = firstBlockNo;
        while (pos < ciphertext.length) {
            int len = (int) Math.min(cipherBS, ciphertext.length - pos);
            byte[] cBlock = new byte[len];
            System.arraycopy(ciphertext, pos, cBlock, 0, len);
            byte[] pBlock = decryptBlock(cBlock, blockNo, fileId);
            out.write(pBlock, 0, pBlock.length);
            pos += len;
            blockNo++;
        }
        return out.toByteArray();
    }

    private static boolean isAllZero(byte[] b) {
        for (byte v : b) {
            if (v != 0) {
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
