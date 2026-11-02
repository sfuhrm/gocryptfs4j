package de.sfuhrm.gocryptfs4j.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.WritableByteChannel;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

/**
 * A reference-counted handle to a single shared {@link CipherFile} per
 * ciphertext path.
 *
 * <p>Several concurrently open channels, streams and whole-file operations on
 * the same plaintext file must not each keep their own {@link CipherFile}:
 * every instance caches the file id and buffers one not-yet-written plaintext
 * block, so a later handle that truncates and rewrites the file (minting a new
 * file id) could be overwritten by a stale handle flushing blocks authenticated
 * with the old id.</p>
 *
 * <p>{@link FileManager} keeps one shared {@link CipherFile} per ciphertext
 * path and hands out these handles. Operations delegate to that shared file,
 * which serializes them on its own monitor. Closing a handle only releases its
 * reference; the underlying channel is closed (flushing any buffered block)
 * once the last reference is released.</p>
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
    }

    /** The shared entry this handle references. */
    private final Entry entry;

    /** Whether this handle was opened for writing. */
    private final boolean writable;

    /** Whether this handle has already been released. */
    private boolean closed;

    /**
     * Creates a handle over the given shared entry.
     *
     * @param entry    the shared entry
     * @param writable whether the handle was opened for writing
     */
    SharedCipherFile(Entry entry, boolean writable) {
        this.entry = Objects.requireNonNull(entry, "entry");
        this.writable = writable;
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
     * Returns the plaintext size of the shared file.
     *
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     */
    public long plainSize() throws IOException {
        synchronized (entry.lock) {
            return file().plainSize();
        }
    }

    /**
     * Reads plaintext bytes at the given offset.
     *
     * @param dst         the destination buffer
     * @param plainOffset the plaintext offset to read from
     * @return the number of bytes read, or {@code -1} at end of file
     * @throws IOException on filesystem or decryption errors
     */
    public int read(ByteBuffer dst, long plainOffset) throws IOException {
        Objects.requireNonNull(dst, "dst");
        synchronized (entry.lock) {
            return file().read(dst, plainOffset);
        }
    }

    /**
     * Writes plaintext bytes at the given offset.
     *
     * @param src         the source buffer
     * @param plainOffset the plaintext offset to write at
     * @return the number of bytes written
     * @throws IOException on filesystem or encryption errors
     */
    public int write(ByteBuffer src, long plainOffset) throws IOException {
        Objects.requireNonNull(src, "src");
        synchronized (entry.lock) {
            return file().write(src, plainOffset);
        }
    }

    /**
     * Truncates the shared file to the given plaintext size.
     *
     * @param newPlainSize the new plaintext size in bytes
     * @throws IOException on filesystem or encryption errors
     */
    public void truncate(long newPlainSize) throws IOException {
        synchronized (entry.lock) {
            file().truncate(newPlainSize);
        }
    }

    /**
     * Forces any pending updates to storage.
     *
     * @param metaData whether metadata updates should be forced as well
     * @throws IOException on filesystem errors
     */
    public void force(boolean metaData) throws IOException {
        synchronized (entry.lock) {
            file().force(metaData);
        }
    }

    /**
     * Opens a streaming, encrypting channel positioned at the given plaintext
     * offset. Closing the channel closes this handle.
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
            } else if (writable) {
                // Other handles keep the shared file open; flush this handle's
                // pending write-back block so closing still persists its writes.
                CipherFile file = entry.file;
                if (file != null) {
                    file.flush();
                }
            }
        }
    }

    /**
     * A streaming, encrypting {@link WritableByteChannel} positioned at a
     * plaintext offset. Closing it releases the enclosing handle.
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
            int n = SharedCipherFile.this.write(src, position);
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
         * Closes the channel and releases the enclosing handle.
         *
         * @throws IOException on filesystem errors
         */
        @Override
        public void close() throws IOException {
            if (open) {
                open = false;
                SharedCipherFile.this.close();
            }
        }
    }
}
