package de.sfuhrm.gocryptfs4j.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;

/**
 * A {@link SeekableByteChannel} over the plaintext of a single encrypted file,
 * backed by the shared {@link BlockCache} of its {@link SharedCipherFile}.
 *
 * <p>All channels on the same shared file use the same block cache, so a block
 * written by one channel is visible to the others and no channel can overwrite
 * another's data with a stale copy. Bytes and ranges are read and written
 * through that cache, which holds one plaintext block at a time and only
 * (de/en)crypts when the position crosses a block boundary or when the channel
 * is flushed. Partial-block writes are merged by loading the whole block,
 * patching it and writing it back.</p>
 *
 * <p>The channel owns the {@link SharedCipherFile} it was created from; closing
 * it releases the handle's reference.</p>
 */
public final class BlockBufferedChannel implements SeekableByteChannel {

    /** The encrypted file backing this channel. */
    private final SharedCipherFile file;

    /** The shared block cache holding the buffered block. */
    private final BlockCache cache;

    /** When buffered writes are flushed to storage. */
    private final SyncPolicy syncPolicy;

    /** The plaintext block size. */
    private final int blockSize;

    /** The current plaintext position. */
    private long position;

    /** Whether the channel permits writes. */
    private final boolean writable;

    /** Whether the channel is open. */
    private boolean open = true;

    /**
     * Creates a channel over the given shared file.
     *
     * @param file     the shared file to read from and write to
     * @param position the initial plaintext position
     * @param writable whether the channel permits writes
     * @param cache    the shared block cache
     */
    BlockBufferedChannel(SharedCipherFile file, long position, boolean writable, BlockCache cache) {
        this(file, position, writable, cache, file.getSyncPolicy());
    }

    /**
     * Creates a channel over the given shared file with an explicit sync policy.
     *
     * @param file       the shared file to read from and write to
     * @param position   the initial plaintext position
     * @param writable   whether the channel permits writes
     * @param cache      the shared block cache
     * @param syncPolicy when buffered writes are flushed to storage
     */
    BlockBufferedChannel(SharedCipherFile file, long position, boolean writable, BlockCache cache,
                         SyncPolicy syncPolicy) {
        this.file = file;
        this.position = position;
        this.writable = writable;
        this.cache = cache;
        this.syncPolicy = SyncPolicy.orDefault(syncPolicy);
        this.blockSize = cache.blockSize();
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
     * Reads plaintext bytes at the current position into {@code dst}, advancing
     * the position by the number of bytes read.
     *
     * @param dst the destination buffer
     * @return the number of bytes read, or {@code -1} at the end of the file
     * @throws ClosedChannelException if the channel is closed
     * @throws IOException on filesystem or decryption errors
     */
    @Override
    public int read(ByteBuffer dst) throws IOException {
        if (!open) {
            throw new ClosedChannelException();
        }
        if (dst.remaining() == 0) {
            return 0;
        }
        long wanted = position / blockSize;
        int off = (int) (position % blockSize);
        int n = cache.read(wanted, off, dst);
        if (n > 0) {
            position += n;
        }
        return n;
    }

    /**
     * Writes plaintext bytes from {@code src} at the current position, advancing
     * the position by the number of bytes written.
     *
     * @param src the source buffer
     * @return the number of bytes written
     * @throws NonWritableChannelException if the channel was opened read-only
     * @throws ClosedChannelException if the channel is closed
     * @throws IOException on filesystem or encryption errors
     */
    @Override
    public int write(ByteBuffer src) throws IOException {
        if (!writable) {
            throw new NonWritableChannelException();
        }
        if (!open) {
            throw new ClosedChannelException();
        }
        if (src.remaining() == 0) {
            return 0;
        }
        long wanted = position / blockSize;
        int off = (int) (position % blockSize);
        int len = Math.min(src.remaining(), blockSize - off);
        int w = cache.write(wanted, off, len, src);
        position += w;
        if (syncPolicy == SyncPolicy.ALWAYS && cache.flush()) {
            file.force(true);
        }
        return w;
    }

    /**
     * Returns the current plaintext position.
     *
     * @return the current position
     */
    @Override
    public long position() {
        return position;
    }

    /**
     * Sets the plaintext position. The buffered block is flushed lazily when the
     * next read or write targets a different block.
     *
     * @param newPosition the new position
     * @return this channel
     * @throws IllegalArgumentException if {@code newPosition} is negative
     */
    @Override
    public SeekableByteChannel position(long newPosition) {
        if (newPosition < 0) {
            throw new IllegalArgumentException("negative position");
        }
        position = newPosition;
        return this;
    }

    /**
     * Returns the plaintext size of the underlying file, including the unflushed
     * write-back of the shared block cache.
     *
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     */
    @Override
    public long size() throws IOException {
        return file.effectiveSize();
    }

    /**
     * Truncates the file to the given plaintext size. As required by
     * {@link SeekableByteChannel#truncate}, the file is not modified when
     * {@code size} is at least the current size. If the current position lies
     * beyond the new size it is moved to the new size.
     *
     * @param size the new plaintext size in bytes
     * @return this channel
     * @throws NonWritableChannelException if the channel was opened read-only
     * @throws IllegalArgumentException if {@code size} is negative
     * @throws IOException on filesystem or encryption errors
     */
    @Override
    public SeekableByteChannel truncate(long size) throws IOException {
        if (!writable) {
            throw new NonWritableChannelException();
        }
        if (size < 0) {
            throw new IllegalArgumentException("negative size");
        }
        cache.flush();
        long current = file.effectiveSize();
        if (size < current) {
            file.truncate(size);
            if (syncPolicy == SyncPolicy.ALWAYS) {
                file.force(true);
            }
        }
        if (position > size) {
            position = size;
        }
        return this;
    }

    /**
     * Forces any pending modifications to be written to the storage device.
     *
     * @param metaData whether metadata updates should be forced as well
     * @throws IOException on filesystem or encryption errors
     */
    public void force(boolean metaData) throws IOException {
        cache.flush();
        file.force(metaData);
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
     * Flushes the shared block cache, if dirty, without closing the channel or
     * forcing it to storage.
     *
     * @throws IOException on filesystem or encryption errors
     */
    public void flush() throws IOException {
        cache.flush();
    }

    /**
     * Closes the channel and releases the underlying shared file. The shared
     * block cache is flushed according to the sync policy, and wiped when the
     * last handle on the shared file is released.
     *
     * @throws IOException on filesystem errors
     */
    @Override
    public void close() throws IOException {
        if (!open) {
            return;
        }
        open = false;
        file.channelClosed(syncPolicy);
    }
}
