package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.FileHeader;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Random-access read/write access to a single encrypted (cipher-side) file.
 *
 * <p>Encapsulates the per-file header (file id) and the block-wise
 * authenticated content encryption (AES-256-GCM, XChaCha20-Poly1305 or
 * AES-SIV, depending on the supplied {@link ContentEnc}), including
 * read-modify-write for partial block writes.</p>
 */
public final class CipherFile implements AutoCloseable {

    /** A shared, immutable empty byte array. */
    private static final byte[] EMPTY = new byte[0];

    /** The underlying cipher file channel. */
    private final FileChannel channel;

    /** The content-encryption helper. */
    private final ContentEnc enc;

    /** Scratch buffer for a single ciphertext block. */
    private final byte[] blockCipher;

    /** Scratch buffer for a single plaintext block. */
    private final byte[] blockPlain;

    /** Scratch buffer for multiple ciphertext blocks, grown on demand. */
    private byte @Nullable [] bulkCipher;

    /** Scratch buffer for multiple plaintext blocks, grown on demand. */
    private byte @Nullable [] bulkPlain;

    /** The file id from the header, or {@code null} for an empty file. */
    private byte @Nullable [] fileId;

    /** Whether the file id has been loaded from the header. */
    private boolean fileIdLoaded;

    /**
     * Creates an instance over an open channel.
     *
     * @param channel the underlying file channel
     * @param enc     the content-encryption helper
     */
    private CipherFile(FileChannel channel, ContentEnc enc) {
        this.channel = channel;
        this.enc = enc;
        this.blockCipher = new byte[(int) enc.cipherBS];
        this.blockPlain = new byte[(int) enc.plainBS];
    }

    /**
     * Ensures the reusable multi-block scratch buffers hold at least
     * {@code blockCount} blocks. The buffers are only ever used by one
     * synchronized operation at a time.
     *
     * @param blockCount the number of blocks the current operation needs
     */
    private void ensureBulk(int blockCount) {
        int cipherLength = (int) (blockCount * enc.cipherBS);
        int plainLength = (int) (blockCount * enc.plainBS);
        if (bulkCipher == null || bulkCipher.length < cipherLength) {
            bulkCipher = new byte[cipherLength];
        }
        if (bulkPlain == null || bulkPlain.length < plainLength) {
            bulkPlain = new byte[plainLength];
        }
    }

    /**
     * Opens a cipher-side file for random access.
     *
     * @param cipherPath the ciphertext-side file path
     * @param enc        the content-encryption helper (determines the cipher)
     * @param writable   whether the file should be opened for writing
     * @return the opened cipher file
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherPath} or {@code enc} is {@code null}
     */
    public static CipherFile open(Path cipherPath, ContentEnc enc, boolean writable) throws IOException {
        Objects.requireNonNull(cipherPath, "cipherPath");
        Objects.requireNonNull(enc, "enc");
        FileChannel ch;
        if (writable) {
            ch = FileChannel.open(cipherPath, StandardOpenOption.READ, StandardOpenOption.WRITE);
        } else {
            ch = FileChannel.open(cipherPath, StandardOpenOption.READ);
        }
        return new CipherFile(ch, enc);
    }

    /**
     * Returns the file id from the header, or {@code null} if the file is empty.
     *
     * @return the 16-byte file id, or {@code null}
     * @throws IOException if the file header is corrupt
     */
    public synchronized byte @Nullable [] fileId() throws IOException {
        if (!fileIdLoaded) {
            long size = channel.size();
            if (size == 0) {
                fileId = null;
            } else {
                byte[] hdr = readCipherRange(0, Constants.HEADER_LEN);
                if (hdr.length < Constants.HEADER_LEN) {
                    throw new IOException("corrupt file header");
                }
                fileId = FileHeader.parse(hdr).id();
            }
            fileIdLoaded = true;
        }
        return fileId;
    }

    /**
     * Returns the plaintext size of the file.
     *
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     */
    public synchronized long plainSize() throws IOException {
        long cipherSize = channel.size();
        if (cipherSize == 0) {
            return 0;
        }
        return enc.cipherSizeToPlainSize(cipherSize);
    }

    /**
     * Reads up to {@code dst.remaining()} plaintext bytes at {@code plainOffset}.
     *
     * @param dst         the destination buffer
     * @param plainOffset the plaintext offset to read from
     * @return number of bytes read, or -1 if at or past end of file
     * @throws IOException on filesystem or decryption errors
     * @throws NullPointerException if {@code dst} is {@code null}
     * @throws IllegalArgumentException if {@code plainOffset} is negative
     */
    public synchronized int read(ByteBuffer dst, long plainOffset) throws IOException {
        Objects.requireNonNull(dst, "dst");
        if (plainOffset < 0) {
            throw new IllegalArgumentException("negative offset: " + plainOffset);
        }
        long size = plainSize();
        if (plainOffset >= size) {
            return -1;
        }
        int maxLen = dst.remaining();
        if (maxLen == 0) {
            return 0;
        }
        long length = Math.min(maxLen, size - plainOffset);

        byte[] fileId = fileId();
        if (fileId == null) {
            return -1;
        }

        long firstBlock = plainOffset / enc.plainBS;
        int skip = (int) (plainOffset % enc.plainBS);
        long lastBlock = (plainOffset + length - 1) / enc.plainBS;
        int blockCount = (int) (lastBlock - firstBlock + 1);

        long cipherOffset = enc.blockNoToCipherOff(firstBlock);
        int cipherLength = (int) (blockCount * enc.cipherBS);
        ensureBulk(blockCount);
        byte[] cipherBuf = Objects.requireNonNull(bulkCipher, "bulkCipher");
        byte[] plainBuf = Objects.requireNonNull(bulkPlain, "bulkPlain");
        int available = readCipherRange(cipherOffset, cipherBuf, cipherLength);

        int plainLength;
        try {
            plainLength = enc.decryptBlocks(cipherBuf, 0, available, firstBlock, fileId, plainBuf, 0);
        } catch (GeneralSecurityException e) {
            throw new IOException("corrupt block in file", e);
        }

        int readable = plainLength - skip;
        if (readable <= 0) {
            return -1;
        }
        int n = Math.min((int) length, readable);
        dst.put(plainBuf, skip, n);
        return n;
    }

    /**
     * Writes {@code src.remaining()} plaintext bytes at {@code plainOffset},
     * performing read-modify-write for partial blocks.
     *
     * @param src         the source buffer
     * @param plainOffset the plaintext offset to write at
     * @return number of bytes written
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code src} is {@code null}
     * @throws IllegalArgumentException if {@code plainOffset} is negative
     */
    public synchronized int write(ByteBuffer src, long plainOffset) throws IOException {
        Objects.requireNonNull(src, "src");
        if (plainOffset < 0) {
            throw new IllegalArgumentException("negative offset: " + plainOffset);
        }
        int length = src.remaining();
        if (length == 0) {
            return 0;
        }

        // Zero-pad any hole up to a block boundary so that the ciphertext file
        // always consists of whole blocks except possibly the last one.
        long oldSize = plainSize();
        if (plainOffset > oldSize) {
            long blockStart = (plainOffset / enc.plainBS) * enc.plainBS;
            if (blockStart > oldSize) {
                writeZeros(oldSize, blockStart - oldSize);
            }
        }

        byte[] fileId = ensureFileId();

        long firstBlock = plainOffset / enc.plainBS;
        long lastBlock = (plainOffset + length - 1) / enc.plainBS;
        int blockCount = (int) (lastBlock - firstBlock + 1);
        ensureBulk(blockCount);
        byte[] cipherBuf = Objects.requireNonNull(bulkCipher, "bulkCipher");
        byte[] plainBuf = Objects.requireNonNull(bulkPlain, "bulkPlain");

        int plainPos = 0;
        for (long b = firstBlock; b <= lastBlock; b++) {
            long blockStart = b * enc.plainBS;
            long lo = Math.max(plainOffset, blockStart);
            long hi = Math.min(plainOffset + length, blockStart + enc.plainBS);
            int segLen = (int) (hi - lo);
            int segSkip = (int) (lo - blockStart);

            if (segSkip == 0 && segLen == enc.plainBS) {
                src.get(plainBuf, plainPos, segLen);
                plainPos += segLen;
            } else {
                byte[] old = readPlainBlock(b);
                int blockPlainLen = Math.max(old.length, segSkip + segLen);
                System.arraycopy(old, 0, plainBuf, plainPos, old.length);
                for (int i = old.length; i < segSkip; i++) {
                    plainBuf[plainPos + i] = 0;
                }
                src.get(plainBuf, plainPos + segSkip, segLen);
                plainPos += blockPlainLen;
            }
        }

        int cipherLength = enc.encryptBlocks(plainBuf, 0, plainPos, firstBlock, fileId, cipherBuf, 0);
        writeCipherRange(enc.blockNoToCipherOff(firstBlock), cipherBuf, 0, cipherLength);
        return length;
    }

    /**
     * Truncates the file to {@code newPlainSize} plaintext bytes.
     *
     * @param newPlainSize the new plaintext size in bytes
     * @throws IOException on filesystem or encryption errors
     * @throws IllegalArgumentException if {@code newPlainSize} is negative
     */
    public synchronized void truncate(long newPlainSize) throws IOException {
        if (newPlainSize < 0) {
            throw new IllegalArgumentException("negative size: " + newPlainSize);
        }
        long oldSize = plainSize();
        if (newPlainSize == oldSize) {
            return;
        }
        if (newPlainSize == 0) {
            channel.truncate(0);
            fileId = null;
            fileIdLoaded = true;
            return;
        }
        byte[] fileId = ensureFileId();

        if (newPlainSize > oldSize) {
            byte[] zeros = new byte[(int) enc.plainBS];
            long remaining = newPlainSize - oldSize;
            long pos = oldSize;
            while (remaining > 0) {
                int n = (int) Math.min(zeros.length, remaining);
                ByteBuffer buf = ByteBuffer.wrap(zeros, 0, n);
                write(buf, pos);
                pos += n;
                remaining -= n;
            }
        } else {
            long blockNo = (newPlainSize - 1) / enc.plainBS;
            long blockStart = blockNo * enc.plainBS;
            int keep = (int) (newPlainSize - blockStart);
            byte[] blockPlain = readPlainBlock(blockNo);
            byte[] truncated = Arrays.copyOf(blockPlain, keep);
            byte[] cipherBlock = enc.encryptBlock(truncated, blockNo, fileId);
            writeCipherRange(enc.blockNoToCipherOff(blockNo), cipherBlock);
            channel.truncate(enc.plainSizeToCipherSize(newPlainSize));
        }
    }

    /**
     * Returns the file id, minting and writing a fresh header if the file is
     * empty.
     *
     * @return the 16-byte file id
     * @throws IOException on filesystem errors
     */
    private byte[] ensureFileId() throws IOException {
        if (!fileIdLoaded) {
            long size = channel.size();
            if (size == 0) {
                fileId = null;
            } else {
                byte[] hdr = readCipherRange(0, Constants.HEADER_LEN);
                if (hdr.length < Constants.HEADER_LEN) {
                    throw new IOException("corrupt file header");
                }
                fileId = FileHeader.parse(hdr).id();
            }
            fileIdLoaded = true;
        }
        if (fileId == null) {
            // The file is empty (or was truncated to empty): mint a fresh header.
            FileHeader h = FileHeader.random();
            writeCipherRange(0, h.pack());
            fileId = h.id();
        }
        return fileId;
    }

    /**
     * Reads and decrypts a whole plaintext block. Empty beyond EOF (gocryptfs
     * semantics).
     *
     * @param blockNo the block number
     * @return the decrypted block, or an empty array past the end of the file
     * @throws IOException on filesystem or decryption errors
     */
    private byte[] readPlainBlock(long blockNo) throws IOException {
        byte[] fileId = fileId();
        long cipherOffset = enc.blockNoToCipherOff(blockNo);
        long cipherSize = channel.size();
        if (cipherOffset >= cipherSize) {
            return EMPTY;
        }
        int len = (int) Math.min(enc.cipherBS, cipherSize - cipherOffset);
        int read = readCipherRange(cipherOffset, blockCipher, len);
        try {
            int n = enc.decryptBlocks(blockCipher, 0, read, blockNo, fileId, blockPlain, 0);
            return Arrays.copyOf(blockPlain, n);
        } catch (GeneralSecurityException e) {
            throw new IOException("corrupt block in file", e);
        }
    }

    /**
     * Zero-fills the plaintext range {@code [offset, offset+length)}.
     *
     * @param offset the plaintext start offset
     * @param length the number of bytes to zero
     * @throws IOException on filesystem or encryption errors
     */
    private void writeZeros(long offset, long length) throws IOException {
        byte[] zeros = new byte[(int) enc.plainBS];
        long remaining = length;
        long pos = offset;
        while (remaining > 0) {
            int n = (int) Math.min(zeros.length, remaining);
            ByteBuffer buf = ByteBuffer.wrap(zeros, 0, n);
            write(buf, pos);
            pos += n;
            remaining -= n;
        }
    }

    /**
     * Reads up to {@code length} ciphertext bytes into a new array.
     *
     * @param offset the ciphertext start offset
     * @param length the maximum number of bytes to read
     * @return the bytes read, possibly fewer than requested or empty at EOF
     * @throws IOException on filesystem errors
     */
    private byte[] readCipherRange(long offset, int length) throws IOException {
        byte[] buf = new byte[length];
        ByteBuffer bb = ByteBuffer.wrap(buf);
        long pos = offset;
        while (bb.hasRemaining()) {
            int n = channel.read(bb, pos);
            if (n < 0) {
                break;
            }
            pos += n;
        }
        if (bb.position() == 0) {
            return EMPTY;
        }
        return Arrays.copyOf(buf, bb.position());
    }

    /**
     * Reads up to {@code length} ciphertext bytes into {@code buf} and returns
     * the byte count.
     *
     * @param offset the ciphertext start offset
     * @param buf    the destination buffer
     * @param length the maximum number of bytes to read
     * @return the number of bytes read
     * @throws IOException on filesystem errors
     */
    private int readCipherRange(long offset, byte[] buf, int length) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(buf, 0, length);
        long pos = offset;
        while (bb.hasRemaining()) {
            int n = channel.read(bb, pos);
            if (n < 0) {
                break;
            }
            pos += n;
        }
        return bb.position();
    }

    /**
     * Writes all of {@code data} at the ciphertext {@code offset}.
     *
     * @param offset the ciphertext start offset
     * @param data   the data to write
     * @throws IOException on filesystem errors
     */
    private void writeCipherRange(long offset, byte[] data) throws IOException {
        writeCipherRange(offset, data, 0, data.length);
    }

    /**
     * Writes a range of {@code data} at the ciphertext {@code offset}.
     *
     * @param offset  the ciphertext start offset
     * @param data    the data buffer
     * @param dataOff the offset within {@code data}
     * @param dataLen the number of bytes to write
     * @throws IOException on filesystem errors
     */
    private void writeCipherRange(long offset, byte[] data, int dataOff, int dataLen) throws IOException {
        ByteBuffer bb = ByteBuffer.wrap(data, dataOff, dataLen);
        long pos = offset;
        while (bb.hasRemaining()) {
            pos += channel.write(bb, pos);
        }
    }

    /**
     * Opens a streaming, encrypting {@link WritableByteChannel} positioned at
     * the given plaintext offset.
     *
     * <p>Writes are performed block-wise and, for partial blocks, use
     * read-modify-write exactly like {@link #write(ByteBuffer, long)}. Closing
     * the returned channel closes this {@link CipherFile}.</p>
     *
     * @param plainOffset the plaintext offset to start writing at
     * @return the encrypting writable channel
     * @throws IOException on filesystem errors
     * @throws IllegalArgumentException if {@code plainOffset} is negative
     */
    public WritableByteChannel writeChannel(long plainOffset) throws IOException {
        if (plainOffset < 0) {
            throw new IllegalArgumentException("negative offset: " + plainOffset);
        }
        return new WriteChannel(plainOffset);
    }

    /**
     * A streaming, encrypting {@link WritableByteChannel} positioned at a
     * plaintext offset. Closing it closes the enclosing cipher file.
     */
    private final class WriteChannel implements WritableByteChannel {

        /** The current plaintext position. */
        private long position;

        /** Whether the channel is open. */
        private boolean open = true;

        /**
         * Creates a channel starting at the given plaintext position.
         *
         * @param position the initial plaintext position
         */
        WriteChannel(long position) {
            this.position = position;
        }

        /**
         * Writes plaintext bytes at the current position.
         *
         * @param src the source buffer
         * @return the number of bytes written
         * @throws IOException on filesystem or encryption errors
         * @throws ClosedChannelException if the channel is closed
         */
        @Override
        public int write(ByteBuffer src) throws IOException {
            if (!open) {
                throw new ClosedChannelException();
            }
            int n = CipherFile.this.write(src, position);
            position += n;
            return n;
        }

        /**
         * Returns whether the channel is open.
         *
         * @return {@code true} if the channel is open
         */
        @Override
        public boolean isOpen() {
            return open;
        }

        /**
         * Closes the channel and the enclosing cipher file.
         *
         * @throws IOException on filesystem errors
         */
        @Override
        public void close() throws IOException {
            if (open) {
                open = false;
                CipherFile.this.close();
            }
        }
    }

    /**
     * Forces any updates to this file to be written to the storage device.
     *
     * @param metaData whether metadata updates should be forced as well
     * @throws IOException on filesystem errors
     */
    public synchronized void force(boolean metaData) throws IOException {
        channel.force(metaData);
    }

    /**
     * Closes the underlying channel.
     *
     * @throws IOException on filesystem errors
     */
    @Override
    public synchronized void close() throws IOException {
        channel.close();
    }
}
