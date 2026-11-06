package de.sfuhrm.gocryptfs4j.core;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.Objects;

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
 * path and hands out these handles. A single shared {@link BlockCache} (one per
 * entry) buffers one plaintext block for all of its channels, so channels on
 * the same file stay coherent. Channels are created per handle via
 * {@link #newChannel(long, boolean)} and tracked by the shared entry so that a
 * filesystem close can flush pending plaintext before the keys are wiped.
 * Closing a handle only releases its reference; the underlying channel is
 * closed once the last reference is released.</p>
 */
public final class SharedCipherFile implements AutoCloseable {

    /** The shared state for one ciphertext path. */
    static final class Entry {

        /** Serializes opening, upgrading, appending and closing the shared file. */
        final Object lock = new Object();

        /** The shared file, or {@code null} when no handle is open. */
        @Nullable volatile CipherFile file;

        /** The number of live handles referencing this entry. */
        int refs;

        /** Whether {@link #file} is currently opened for writing. */
        boolean writable;

        /**
         * The single shared block cache, created lazily by {@link #newChannel}.
         * All channels on this entry share it so their writes are coherent.
         */
        @Nullable volatile BlockCache cache;

        @Nullable volatile IOException failure;
    }

    /** The shared entry this handle references. */
    private final Entry entry;

    /** When buffered writes are flushed to storage. */
    private final SyncPolicy syncPolicy;

    /** Whether this handle has already been released. */
    private boolean closed;

    /**
     * Creates a handle over the given shared entry, flushing on close.
     *
     * @param entry the shared entry
     */
    SharedCipherFile(Entry entry) {
        this(entry, SyncPolicy.ON_CLOSE);
    }

    /**
     * Creates a handle over the given shared entry.
     *
     * @param entry      the shared entry
     * @param syncPolicy when buffered writes are flushed to storage
     */
    SharedCipherFile(Entry entry, SyncPolicy syncPolicy) {
        this.entry = Objects.requireNonNull(entry, "entry");
        this.syncPolicy = SyncPolicy.orDefault(syncPolicy);
    }

    /**
     * Returns when buffered writes are flushed to storage.
     *
     * @return the sync policy
     */
    public SyncPolicy getSyncPolicy() {
        return syncPolicy;
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
        // A dirty block in the shared cache would otherwise survive a shrink or
        // truncate-to-empty performed by another handle and be written back
        // later, resurrecting the truncated data. Flush the cache first so no
        // stale block outlives the truncation.
        flushEntry(entry);
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
        flushEntry(entry);
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
        return newChannel(position, writable, syncPolicy);
    }

    /**
     * Opens a buffered, random-access channel over this file at the given
     * plaintext position, using the given sync policy. The returned channel
     * owns this handle; closing it releases this handle's reference.
     *
     * @param position   the initial plaintext position
     * @param writable   whether the channel permits writes
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the buffered channel
     * @throws IOException on filesystem errors
     * @throws IllegalArgumentException if {@code position} is negative
     */
    public BlockBufferedChannel newChannel(long position, boolean writable, SyncPolicy syncPolicy)
            throws IOException {
        if (position < 0) {
            throw new IllegalArgumentException("negative position: " + position);
        }
        BlockCache cache;
        synchronized (entry.lock) {
            cache = entry.cache;
            if (cache == null) {
                cache = new BlockCache(entry, blockSize());
                entry.cache = cache;
            }
        }
        BlockBufferedChannel ch = new BlockBufferedChannel(this, position, writable, cache,
                SyncPolicy.orDefault(syncPolicy));
        return ch;
    }

    /**
     * Returns the monitor that serializes append operations on this entry, so
     * that looking up the end of the file and writing to it form one atomic
     * step for all appenders on the same file.
     *
     * @return the append monitor
     */
    Object appendLock() {
        return entry.lock;
    }

    /**
     * Called by a channel on close: releases this handle's reference.
     *
     * @throws IOException on filesystem errors
     */
    void channelClosed() throws IOException {
        close();
    }

    /**
     * Called by a channel on close with the channel's sync policy.
     *
     * @param syncPolicy the channel's sync policy
     * @throws IOException on filesystem errors
     */
    void channelClosed(SyncPolicy syncPolicy) throws IOException {
        release(SyncPolicy.orDefault(syncPolicy));
    }

    /**
     * Returns the effective plaintext size of an entry, including the unflushed
     * write-back of the shared block cache. The on-disk plaintext size alone
     * misses a block that a channel has buffered but not yet written through.
     *
     * @param entry the shared entry
     * @return the plaintext size including buffered data
     * @throws IOException on filesystem errors
     */
    static long effectiveSize(Entry entry) throws IOException {
        long size = entry.file == null ? 0 : entry.file.plainSize();
        BlockCache cache = entry.cache;
        if (cache != null) {
            size = Math.max(size, cache.writeBackSize());
        }
        return size;
    }

    /**
     * Returns the effective plaintext size of this handle's file, including the
     * unflushed write-back of the shared block cache.
     *
     * @return the plaintext size including buffered data
     * @throws IOException on filesystem errors
     */
    long effectiveSize() throws IOException {
        return effectiveSize(entry);
    }

    /**
     * Flushes and invalidates the shared block cache of this entry, so the next
     * access reloads the current on-disk content.
     *
     * @throws IOException on filesystem or encryption errors
     */
    void flushChannels() throws IOException {
        flushEntry(entry);
    }

    /**
     * Flushes the shared block cache of this entry.
     *
     * @param entry the shared entry
     * @return {@code true} if a modified block was written
     * @throws IOException on filesystem or encryption errors
     */
    static boolean flushEntry(Entry entry) throws IOException {
        BlockCache cache = entry.cache;
        if (cache != null) {
            try {
                boolean wrote = cache.flush();
                entry.failure = null;
                return wrote;
            } catch (IOException e) {
                entry.failure = e;
                throw e;
            }
        }
        return false;
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
        release(syncPolicy);
    }

    /**
     * Releases this handle's reference using the given sync policy.
     *
     * @param syncPolicy when buffered writes are flushed to storage
     * @throws IOException on filesystem errors
     */
    private void release(SyncPolicy syncPolicy) throws IOException {
        synchronized (entry.lock) {
            if (closed) {
                return;
            }
            closed = true;
            entry.refs--;
            boolean last = entry.refs == 0;
            CipherFile file = entry.file;
            BlockCache cache = entry.cache;
            IOException failure = null;
            boolean wrote = false;

            // Flush on every channel close (the default policy), not only on
            // the last one: a write() that closes its channel must be visible
            // to other processes while another handle is still open. NONE
            // keeps the old batching behaviour and flushes only at last close.
            if (cache != null && file != null && (last || syncPolicy != SyncPolicy.NONE)) {
                try {
                    wrote = flushEntry(entry);
                } catch (IOException e) {
                    failure = e;
                }
            }

            if (!last && file != null && failure == null && wrote
                    && syncPolicy != SyncPolicy.NONE) {
                try {
                    file.force(true);
                } catch (IOException e) {
                    failure = e;
                }
            }

            if (last) {
                if (cache != null) {
                    // No handle is left that could retry a failed flush, so do
                    // not retain plaintext after the file itself is closed.
                    cache.wipe();
                }
                entry.file = null;
                entry.cache = null;
                if (file != null) {
                    try {
                        file.close();
                    } catch (IOException e) {
                        if (failure == null) {
                            failure = e;
                        } else {
                            failure.addSuppressed(e);
                        }
                    }
                }
            } else if (failure != null) {
                // Keep the dirty block so a later close or force on another
                // still-open handle can retry the failed write.
                entry.failure = failure;
            }

            if (failure != null) {
                entry.failure = failure;
                throw failure;
            }
        }
    }
}
