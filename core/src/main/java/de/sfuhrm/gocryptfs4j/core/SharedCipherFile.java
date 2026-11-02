package de.sfuhrm.gocryptfs4j.core;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.Nullable;

/**
 * A reference-counted handle to a single shared {@link CipherFile} per
 * ciphertext path.
 *
 * <p>Several concurrently open channels, streams and whole-file operations on
 * the same plaintext file must not each keep their own {@link CipherFile}:
 * every instance caches the file id, so a later handle that truncates and
 * rewrites the file (minting a new file id) could be overwritten by a stale
 * handle encrypting blocks with the old id.</p>
 *
 * <p>{@link FileManager} keeps one shared {@link CipherFile} per ciphertext
 * path and hands out these handles. Block buffering lives in
 * {@link BlockBufferedChannel}, which is created per handle via
 * {@link #newChannel(long, boolean)} and tracked by the shared entry so that a
 * filesystem close can flush pending plaintext before the keys are wiped.
 * Closing a handle only releases its reference; the underlying channel is
 * closed once the last reference is released.</p>
 */
public final class SharedCipherFile implements AutoCloseable {

    /** The shared state for one ciphertext path. */
    static final class Entry {

        /** Serializes opening, upgrading and closing the shared file. */
        final Object lock = new Object();

        /** The shared file, or {@code null} when no handle is open. */
        @Nullable CipherFile file;

        /** The number of live handles referencing this entry. */
        int refs;

        /** Whether {@link #file} is currently opened for writing. */
        boolean writable;

        /** Open buffered channels, tracked so a filesystem close can flush them. */
        final Set<BlockBufferedChannel> channels = Collections.newSetFromMap(
                new IdentityHashMap<BlockBufferedChannel, Boolean>());
    }

    /** The shared entry this handle references. */
    private final Entry entry;

    /** Whether this handle has already been released. */
    private boolean closed;

    /**
     * Creates a handle over the given shared entry.
     *
     * @param entry the shared entry
     */
    SharedCipherFile(Entry entry) {
        this.entry = Objects.requireNonNull(entry, "entry");
    }

    /**
     * Returns the shared file, failing if the handle has no live backing file.
     *
     * @return the shared file
     * @throws ClosedChannelException if the handle is already closed
     */
    private CipherFile file() throws IOException {
        CipherFile file = entry.file;
        if (file == null) {
            throw new ClosedChannelException();
        }
        return file;
    }

    /**
     * Returns the plaintext block size of the shared file.
     *
     * @return the plaintext block size in bytes
     * @throws IOException on filesystem errors
     */
    int blockSize() throws IOException {
        return file().blockSize();
    }

    /**
     * Returns the plaintext size of the shared file.
     *
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     */
    public long plainSize() throws IOException {
        return file().plainSize();
    }

    /**
     * Reads and decrypts a whole plaintext block.
     *
     * @param blockNo the block number
     * @param out     the destination buffer
     * @param off     the destination offset
     * @return the number of valid plaintext bytes, or zero past EOF
     * @throws IOException on filesystem or decryption errors
     */
    int readBlock(long blockNo, byte[] out, int off) throws IOException {
        return file().readBlock(blockNo, out, off);
    }

    /**
     * Encrypts and writes a whole plaintext block.
     *
     * @param blockNo the block number
     * @param plain   the plaintext buffer
     * @param off     the plaintext offset
     * @param len     the number of plaintext bytes
     * @throws IOException on filesystem or encryption errors
     */
    void writeBlock(long blockNo, byte[] plain, int off, int len) throws IOException {
        file().writeBlock(blockNo, plain, off, len);
    }

    /**
     * Truncates the shared file to the given plaintext size, growing (with
     * zero-fill) or shrinking as needed.
     *
     * @param newPlainSize the new plaintext size in bytes
     * @throws IOException on filesystem or encryption errors
     * @throws IllegalArgumentException if {@code newPlainSize} is negative
     */
    public void truncate(long newPlainSize) throws IOException {
        if (newPlainSize < 0) {
            throw new IllegalArgumentException("negative size: " + newPlainSize);
        }
        if (newPlainSize == 0) {
            file().truncate(0);
            return;
        }
        long oldSize = file().plainSize();
        if (newPlainSize == oldSize) {
            return;
        }
        if (newPlainSize < oldSize) {
            file().truncate(newPlainSize);
            return;
        }
        // Grow: append zeros, completing the final partial block of the old
        // content and zero-filling up to the new size.
        long remaining = newPlainSize - oldSize;
        try (BlockBufferedChannel ch = newChannel(oldSize, true)) {
            byte[] zeros = new byte[blockSize()];
            while (remaining > 0) {
                int n = (int) Math.min(zeros.length, remaining);
                int w = ch.write(java.nio.ByteBuffer.wrap(zeros, 0, n));
                if (w <= 0) {
                    throw new IOException("no progress growing file");
                }
                remaining -= w;
            }
        }
    }

    /**
     * Forces any pending updates to storage.
     *
     * @param metaData whether metadata updates should be forced as well
     * @throws IOException on filesystem errors
     */
    public void force(boolean metaData) throws IOException {
        file().force(metaData);
    }

    /**
     * Opens a buffered, random-access channel over this file at the given
     * plaintext position. The returned channel owns this handle; closing it
     * releases this handle's reference.
     *
     * @param position the initial plaintext position
     * @param writable whether the channel permits writes
     * @return the buffered channel
     * @throws IOException on filesystem errors
     * @throws IllegalArgumentException if {@code position} is negative
     */
    public BlockBufferedChannel newChannel(long position, boolean writable) throws IOException {
        if (position < 0) {
            throw new IllegalArgumentException("negative position: " + position);
        }
        BlockBufferedChannel ch = new BlockBufferedChannel(this, position, writable, blockSize());
        entry.channels.add(ch);
        return ch;
    }

    /**
     * Called by a channel on close: unregisters it and releases this handle's
     * reference.
     *
     * @param ch the closing channel
     * @throws IOException on filesystem errors
     */
    void channelClosed(BlockBufferedChannel ch) throws IOException {
        entry.channels.remove(ch);
        close();
    }

    /**
     * Flushes the buffered block of every open channel of this entry.
     *
     * @param entry the shared entry
     * @throws IOException on filesystem or encryption errors
     */
    static void flushEntry(Entry entry) throws IOException {
        for (BlockBufferedChannel ch : entry.channels) {
            ch.flush();
        }
    }

    /**
     * Releases this handle's reference to the shared file, closing the
     * underlying channel when the last reference is released. Calling this
     * method more than once has no effect.
     *
     * @throws IOException on filesystem errors
     */
    @Override
    public void close() throws IOException {
        synchronized (entry.lock) {
            if (closed) {
                return;
            }
            closed = true;
            entry.refs--;
            if (entry.refs == 0) {
                CipherFile file = entry.file;
                if (file != null) {
                    try {
                        file.close();
                    } finally {
                        entry.file = null;
                    }
                }
            }
        }
    }
}
