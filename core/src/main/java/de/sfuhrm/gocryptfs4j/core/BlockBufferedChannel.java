package de.sfuhrm.gocryptfs4j.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.util.Arrays;

/**
 * A {@link SeekableByteChannel} over the plaintext of a single encrypted file,
 * buffering one plaintext block at a time.
 *
 * <p>Bytes and ranges are read and written through a single in-memory block;
 * the block is only (de/en)crypted when the position crosses a block boundary
 * or when the channel is closed or forced. Partial-block writes are merged by
 * loading the whole block, patching it and writing it back, so arbitrary
 * plaintext positions and lengths are supported without a per-byte
 * encryption cost.</p>
 *
 * <p>The channel owns the {@link SharedCipherFile} it was created from; closing
 * it releases the handle's reference.</p>
 */
public final class BlockBufferedChannel implements SeekableByteChannel {

    /** The encrypted file backing this channel. */
    private final SharedCipherFile file;

    /** The plaintext block size. */
    private final int blockSize;

    /** The plaintext of the currently loaded block. */
    private final byte[] block;

    /** The block number currently buffered, or {@code -1} if none. */
    private long blockNo = -1;

    /** The number of valid plaintext bytes in {@link #block}. */
    private int blockLen;

    /** Whether {@link #block} has unflushed modifications. */
    private boolean dirty;

    /** The current plaintext position. */
    private long position;

    /** Whether the channel permits writes. */
    private final boolean writable;

    /** Whether the channel is open. */
    private boolean open = true;

    /**
     * Creates a channel over the given shared file.
     *
     * @param file       the shared file to read from and write to
     * @param position   the initial plaintext position
     * @param writable   whether the channel permits writes
     * @param blockSize  the plaintext block size
     */
    BlockBufferedChannel(SharedCipherFile file, long position, boolean writable, int blockSize) {
        this.file = file;
        this.position = position;
        this.writable = writable;
        this.blockSize = blockSize;
        this.block = new byte[blockSize];
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
        if (wanted != blockNo) {
            flushBlock();
            loadBlock(wanted);
        }
        int off = (int) (position % blockSize);
        if (off >= blockLen) {
            return -1;
        }
        int n = Math.min(dst.remaining(), blockLen - off);
        dst.put(block, off, n);
        position += n;
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
        if (wanted != blockNo) {
            flushBlock();
            // A write far behind EOF would leave the current final partial
            // block followed by a zero hole. Zero-pad that block first so it
            // stays a whole, authentic block.
            long plainSize = file.plainSize();
            if (plainSize > 0
                    && plainSize % blockSize != 0
                    && wanted > (plainSize - 1) / blockSize) {
                file.zeroPad();
            }
            loadBlock(wanted);
        }
        int off = (int) (position % blockSize);
        int n = Math.min(src.remaining(), blockSize - off);
        if (off > blockLen) {
            // The write starts past the current valid data, leaving a hole
            // inside the block. Zero it out instead of encrypting stale bytes
            // left over from a previously buffered block.
            Arrays.fill(block, blockLen, off, (byte) 0);
        }
        src.get(block, off, n);
        if (off + n > blockLen) {
            blockLen = off + n;
        }
        dirty = true;
        position += n;
        return n;
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
     * Returns the plaintext size of the underlying file, including any unflushed
     * modifications to the currently buffered block.
     *
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     */
    @Override
    public long size() throws IOException {
        long size = file.plainSize();
        if (dirty) {
            size = Math.max(size, blockNo * blockSize + blockLen);
        }
        return size;
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
        flushBlock();
        long current = file.plainSize();
        if (size < current) {
            file.truncate(size);
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
        flushBlock();
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
     * Flushes the buffered block, if dirty, without closing the channel or
     * forcing it to storage.
     *
     * @throws IOException on filesystem or encryption errors
     */
    public void flush() throws IOException {
        flushBlock();
    }

    /**
     * Closes the channel, flushing any buffered block, wiping the plaintext
     * buffer and releasing the underlying shared file.
     *
     * @throws IOException on filesystem errors
     */
    @Override
    public void close() throws IOException {
        if (!open) {
            return;
        }
        open = false;
        try {
            flushBlock();
        } finally {
            Arrays.fill(block, (byte) 0);
            file.channelClosed(this);
        }
    }

    /**
     * Loads the plaintext of block {@code no} into {@link #block}, setting
     * {@link #blockLen} to the number of valid bytes in it (zero past EOF).
     *
     * @param no the block number
     * @throws IOException on filesystem or decryption errors
     */
    private void loadBlock(long no) throws IOException {
        blockNo = no;
        blockLen = file.readBlock(no, block, 0);
        Arrays.fill(block, blockLen, blockSize, (byte) 0);
        dirty = false;
    }

    /**
     * Writes the buffered block back to the file if it was modified, then
     * invalidates it so the next access reloads the current content.
     *
     * @throws IOException on filesystem or encryption errors
     */
    private void flushBlock() throws IOException {
        if (dirty) {
            file.writeBlock(blockNo, block, 0, blockLen);
        }
        blockNo = -1;
        blockLen = 0;
        dirty = false;
    }
}
