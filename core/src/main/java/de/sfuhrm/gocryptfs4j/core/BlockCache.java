package de.sfuhrm.gocryptfs4j.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.util.Arrays;

/**
 * The single shared plaintext block cache of one cipher file.
 *
 * <p>Every open channel on the same {@link SharedCipherFile} shares this one
 * cache instead of keeping its own buffered block. A block written by one
 * channel is therefore immediately visible to every other channel, no channel
 * can overwrite another's data with a stale copy, and there is only a single
 * unflushed write-back to account for when reporting sizes.</p>
 *
 * <p>The cache holds at most one block. Accessing a different block flushes the
 * current one (if it was modified) and loads the requested one. All access is
 * serialized on the shared entry's monitor, together with truncation and
 * growth of the file, so concurrent channels on the same file cannot interleave
 * load-patch-flush sequences and a flush cannot be split from a size change.</p>
 */
final class BlockCache {

    /** The shared entry, used to resolve the current backing file. */
    private final SharedCipherFile.Entry entry;

    /** The plaintext of the currently cached block. */
    private final byte[] block;

    /** The cached block number, or {@code -1} if none. */
    private long blockNo = -1;

    /** The number of valid plaintext bytes in {@link #block}. */
    private int blockLen;

    /** Whether {@link #block} has unflushed modifications. */
    private boolean dirty;

    /**
     * Creates a cache over the given shared entry.
     *
     * @param entry     the shared entry
     * @param blockSize the plaintext block size in bytes
     */
    BlockCache(SharedCipherFile.Entry entry, int blockSize) {
        this.entry = entry;
        this.block = new byte[blockSize];
    }

    /**
     * Returns the plaintext block size in bytes.
     *
     * @return the block size
     */
    int blockSize() {
        return block.length;
    }

    /**
     * Resolves the current backing file.
     *
     * @return the shared file
     * @throws ClosedChannelException if the file is closed
     */
    private CipherFile file() throws IOException {
        CipherFile file = entry.file;
        if (file == null) {
            throw new ClosedChannelException();
        }
        return file;
    }

    /**
     * Flushes the cached block back to the file if it was modified, then
     * invalidates it so the next access reloads the current content.
     *
     * @return {@code true} if a modified block was written
     * @throws IOException on filesystem or encryption errors
     */
    boolean flush() throws IOException {
        synchronized (entry.lock) {
            boolean wrote = dirty;
            if (dirty) {
                file().writeBlock(blockNo, block, 0, blockLen);
            }
            blockNo = -1;
            blockLen = 0;
            dirty = false;
            return wrote;
        }
    }

    /**
     * Returns the plaintext size the cached block would extend the file to, or
     * {@code -1} if the cached block is not dirty.
     *
     * @return the write-back size, or {@code -1}
     */
    long writeBackSize() {
        synchronized (entry.lock) {
            return dirty ? blockNo * blockSize() + blockLen : -1;
        }
    }

    /**
     * Reads plaintext bytes of block {@code no} starting at {@code off} into
     * {@code dst}. The block is loaded if it is not already cached.
     *
     * @param no  the block number
     * @param off the plaintext offset within the block
     * @param dst the destination buffer
     * @return the number of bytes read, or {@code -1} at the end of the file
     * @throws IOException on filesystem or decryption errors
     */
    int read(long no, int off, ByteBuffer dst) throws IOException {
        synchronized (entry.lock) {
            load(no);
            if (off >= blockLen) {
                return -1;
            }
            int n = Math.min(dst.remaining(), blockLen - off);
            dst.put(block, off, n);
            return n;
        }
    }

    /**
     * Writes {@code len} plaintext bytes from {@code src} into block {@code no}
     * at offset {@code off}, patching the cached block and marking it dirty.
     * The block is loaded first if it is not already cached.
     *
     * @param no  the block number
     * @param off the plaintext offset within the block
     * @param len the number of bytes to write
     * @param src the source buffer
     * @return the number of bytes written
     * @throws IOException on filesystem or encryption errors
     */
    int write(long no, int off, int len, ByteBuffer src) throws IOException {
        synchronized (entry.lock) {
            if (blockNo != no) {
                flush();
                padFinalPartialBlock(no);
                load(no);
            } else if (!dirty) {
                // The target block is already cached (e.g. a read at a hole
                // position loaded it), but a write into it would still leave a
                // hole after the final partial block. Pad that block here as
                // well.
                padFinalPartialBlock(no);
            }
            if (off > blockLen) {
                // The write starts past the current valid data, leaving a hole
                // inside the block. Zero it out instead of encrypting stale
                // bytes left over from a previously cached block.
                Arrays.fill(block, blockLen, off, (byte) 0);
            }
            src.get(block, off, len);
            if (off + len > blockLen) {
                blockLen = off + len;
            }
            dirty = true;
            return len;
        }
    }

    /**
     * Wipes the plaintext buffer and invalidates the cache.
     */
    void wipe() {
        synchronized (entry.lock) {
            Arrays.fill(block, (byte) 0);
            blockNo = -1;
            blockLen = 0;
            dirty = false;
        }
    }

    /**
     * Loads block {@code no} into {@link #block}, flushing the current block
     * first if a different one is cached.
     *
     * @param no the block number
     * @throws IOException on filesystem or decryption errors
     */
    private void load(long no) throws IOException {
        if (blockNo != no) {
            flush();
            blockNo = no;
            blockLen = file().readBlock(no, block, 0);
            Arrays.fill(block, blockLen, blockSize(), (byte) 0);
            dirty = false;
        }
    }

    /**
     * Pads the final partial plaintext block of the file with zeros up to the
     * full block size, but only when {@code wanted} targets a block beyond the
     * last valid byte. Writing such a block would leave the partial block
     * followed by a zero hole, which would no longer authenticate when read
     * back.
     *
     * @param wanted the block number about to be written
     * @throws IOException on filesystem or encryption errors
     */
    private void padFinalPartialBlock(long wanted) throws IOException {
        long plainSize = file().plainSize();
        if (plainSize > 0
                && plainSize % blockSize() != 0
                && wanted > (plainSize - 1) / blockSize()) {
            file().zeroPad();
        }
    }
}
