package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.CipherFile;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;

/**
 * A {@link SeekableByteChannel} over a single encrypted file, exposing the
 * decrypted (plaintext) content.
 *
 * <p>The channel keeps a plaintext position and delegates all reads and writes
 * to a {@link CipherFile}. Read and write access are controlled independently by
 * the {@code readable} and {@code writable} flags. Updates may optionally be
 * forced to storage, according to the {@link Sync} mode, and an optional
 * {@link CloseAction} runs after the underlying file has been closed (used for
 * {@link java.nio.file.StandardOpenOption#DELETE_ON_CLOSE}).</p>
 */
final class GocryptFsFileChannel implements SeekableByteChannel {

    /**
     * How updates are forced to storage after a write or truncation.
     */
    enum Sync {
        /** Do not force; updates may remain in the operating system cache. */
        NONE,
        /** Force file content only (DSYNC). */
        DATA,
        /** Force file content and metadata (SYNC). */
        FULL
    }

    /**
     * An action to run when the channel is closed.
     */
    interface CloseAction {
        /**
         * Runs the action.
         *
         * @throws IOException if the action fails
         */
        void run() throws IOException;
    }

    /** The encrypted file backing this channel. */
    private final CipherFile file;

    /** Whether the channel permits reads. */
    private final boolean readable;

    /** Whether the channel permits writes and truncation. */
    private final boolean writable;

    /** How updates are forced to storage. */
    private final Sync sync;

    /** The action to run on close, or {@code null} for none. */
    private final @Nullable CloseAction closeAction;

    /** The current plaintext position. */
    private long position;

    /** Whether the channel is still open. */
    private boolean open = true;

    /**
     * Creates a channel.
     *
     * @param file            the encrypted file to read from and write to
     * @param readable        whether the channel permits reads
     * @param writable        whether the channel permits writes and truncation
     * @param initialPosition the initial plaintext position
     * @param sync            how updates are forced to storage
     * @param closeAction     an action to run on close, or {@code null} for none
     */
    GocryptFsFileChannel(CipherFile file, boolean readable, boolean writable,
                         long initialPosition, Sync sync, @Nullable CloseAction closeAction) {
        this.file = file;
        this.readable = readable;
        this.writable = writable;
        this.position = initialPosition;
        this.sync = sync;
        this.closeAction = closeAction;
    }

    /**
     * Reads a sequence of plaintext bytes into {@code dst} starting at the
     * current position, advancing the position by the number of bytes read.
     *
     * @param dst the destination buffer
     * @return the number of bytes read, possibly zero, or {@code -1} at the end of the file
     * @throws NonReadableChannelException if the channel was opened write-only
     * @throws IOException on filesystem or decryption errors
     */
    @Override
    public int read(ByteBuffer dst) throws IOException {
        if (!readable) {
            throw new NonReadableChannelException();
        }
        int n = file.read(dst, position);
        if (n > 0) {
            position += n;
        }
        return n;
    }

    /**
     * Writes a sequence of plaintext bytes from {@code src} starting at the
     * current position, advancing the position by the number of bytes written
     * and forcing the update if a sync mode is active.
     *
     * @param src the source buffer
     * @return the number of bytes written, possibly zero
     * @throws NonWritableChannelException if the channel was opened read-only
     * @throws IOException on filesystem or encryption errors
     */
    @Override
    public int write(ByteBuffer src) throws IOException {
        if (!writable) {
            throw new NonWritableChannelException();
        }
        int n = file.write(src, position);
        position += n;
        force();
        return n;
    }

    /**
     * Forces pending updates according to the channel's sync mode.
     *
     * @throws IOException on filesystem errors
     */
    private void force() throws IOException {
        if (sync == Sync.FULL) {
            file.force(true);
        } else if (sync == Sync.DATA) {
            file.force(false);
        }
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
     * Sets the plaintext position.
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
        this.position = newPosition;
        return this;
    }

    /**
     * Returns the plaintext size of the underlying file.
     *
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     */
    @Override
    public long size() throws IOException {
        return file.plainSize();
    }

    /**
     * Truncates the file to the given plaintext size, forcing the update if a
     * sync mode is active. If the current position lies beyond the new size it
     * is moved to the new size.
     *
     * @param size the new plaintext size in bytes
     * @return this channel
     * @throws NonWritableChannelException if the channel was opened read-only
     * @throws IOException on filesystem or encryption errors
     */
    @Override
    public SeekableByteChannel truncate(long size) throws IOException {
        if (!writable) {
            throw new NonWritableChannelException();
        }
        file.truncate(size);
        force();
        if (position > size) {
            position = size;
        }
        return this;
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
     * Closes the channel and, if present, runs the close action.
     *
     * @throws IOException if closing the underlying file or the close action fails
     */
    @Override
    public void close() throws IOException {
        if (open) {
            open = false;
            try {
                file.close();
            } finally {
                if (closeAction != null) {
                    closeAction.run();
                }
            }
        }
    }
}
