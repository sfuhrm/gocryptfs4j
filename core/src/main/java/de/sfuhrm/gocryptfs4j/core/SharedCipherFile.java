package de.sfuhrm.gocryptfs4j.core;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

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
         * Read-only files replaced by a read-to-write upgrade. They stay open
         * until the entry is fully released so a reader that already captured
         * one cannot observe a closed channel.
         */
        final List<CipherFile> retired = new ArrayList<>();

        /**
         * The single shared block cache, created lazily by {@link #newChannel}.
         * All channels on this entry share it so their writes are coherent.
         */
        @Nullable volatile BlockCache cache;

        @Nullable volatile IOException failure;

        /** The map key under which {@link FileManager} currently stores this entry. */
        @Nullable volatile String key;

        /**
         * Called after the last handle is released so the owner can drop this
         * entry from its registry. {@code null} for entries not kept in a map.
         */
        @Nullable Consumer<Entry> releaseAction;
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
        CipherFile file = file();
        if (newPlainSize == 0) {
            file.truncate(0);
            return;
        }
        long oldSize = file.plainSize();
        if (newPlainSize == oldSize) {
            return;
        }
        if (newPlainSize < oldSize) {
            file.truncate(newPlainSize);
            return;
        }
        grow(file, oldSize, newPlainSize);
    }

    /**
     * Grows the file sparsely by writing only the blocks that cannot stay as
     * holes: the old final partial block is zero-padded, and the new final
     * block is written with zeros. Everything in between remains a sparse hole,
     * so growing to a huge size does not write the whole range.
     *
     * @param file         the shared file
     * @param oldSize      the current plaintext size
     * @param newPlainSize the target plaintext size
     * @throws IOException on filesystem or encryption errors
     */
    private void grow(CipherFile file, long oldSize, long newPlainSize) throws IOException {
        long blockSize = file.blockSize();
        long oldBlock = oldSize / blockSize;
        int oldOffset = (int) (oldSize % blockSize);
        long lastBlock = (newPlainSize - 1) / blockSize;
        int lastLength = (int) (newPlainSize - lastBlock * blockSize);

        if (oldSize > 0 && oldOffset > 0) {
            if (lastBlock == oldBlock) {
                // The new end is in the same block as the old end: keep the
                // existing bytes and zero-fill the rest of that block.
                byte[] block = new byte[(int) blockSize];
                int len = file.readBlock(oldBlock, block, 0);
                Arrays.fill(block, len, lastLength, (byte) 0);
                file.writeBlock(oldBlock, block, 0, lastLength);
                return;
            }
            // The hole would start after a partial ciphertext block, which
            // cannot be authenticated when read back. Pad it to a full block.
            file.zeroPad();
        }

        // Write only the final block; the blocks before it stay sparse. This
        // also mints the file header when the file was empty.
        byte[] zeros = new byte[(int) blockSize];
        file.writeBlock(lastBlock, zeros, 0, lastLength);
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
     * plaintext position. The channel takes its own reference to the shared
     * file; closing it does not close this handle, which the caller still has
     * to close.
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
     * plaintext position, using the given sync policy. The channel takes its
     * own reference to the shared file; closing it does not close this handle,
     * which the caller still has to close.
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
        SharedCipherFile channelFile;
        synchronized (entry.lock) {
            CipherFile file = entry.file;
            if (file == null) {
                throw new ClosedChannelException();
            }
            cache = entry.cache;
            if (cache == null) {
                cache = new BlockCache(entry, file.blockSize());
                entry.cache = cache;
            }
            // The channel owns its own reference, so closing it does not
            // release the caller's handle (and vice versa).
            entry.refs++;
            channelFile = new SharedCipherFile(entry, syncPolicy);
        }
        try {
            return new BlockBufferedChannel(channelFile, position, writable, cache,
                    SyncPolicy.orDefault(syncPolicy));
        } catch (RuntimeException e) {
            try {
                channelFile.close();
            } catch (IOException closeFailure) {
                e.addSuppressed(closeFailure);
            }
            throw e;
        }
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
        synchronized (entry.lock) {
            CipherFile file = entry.file;
            long size = file == null ? 0 : file.plainSize();
            BlockCache cache = entry.cache;
            if (cache != null) {
                size = Math.max(size, cache.writeBackSize());
            }
            return size;
        }
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
        IOException failure;
        Consumer<Entry> releaseAction;
        synchronized (entry.lock) {
            if (closed) {
                return;
            }
            closed = true;
            entry.refs--;
            boolean last = entry.refs == 0;
            CipherFile file = entry.file;
            BlockCache cache = entry.cache;
            failure = null;
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
                for (CipherFile retired : entry.retired) {
                    try {
                        retired.close();
                    } catch (IOException e) {
                        if (failure == null) {
                            failure = e;
                        } else {
                            failure.addSuppressed(e);
                        }
                    }
                }
                entry.retired.clear();
            } else if (failure != null) {
                // Keep the dirty block so a later close or force on another
                // still-open handle can retry the failed write.
                entry.failure = failure;
            }

            if (failure != null) {
                entry.failure = failure;
            }
            releaseAction = last ? entry.releaseAction : null;
        }
        // The registry callback must run outside this entry's monitor: it
        // takes the map's lock and then re-checks the entry under this lock.
        if (releaseAction != null) {
            releaseAction.accept(entry);
        }
        if (failure != null) {
            throw failure;
        }
    }
}
