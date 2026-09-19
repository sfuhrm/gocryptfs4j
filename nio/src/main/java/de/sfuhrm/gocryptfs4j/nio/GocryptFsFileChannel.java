package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.CipherFile;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;

/** A {@link SeekableByteChannel} over an encrypted file, exposing plaintext. */
final class GocryptFsFileChannel implements SeekableByteChannel {

    /** How updates are forced to storage after a write. */
    enum Sync {
        /** Do not force. */
        NONE,
        /** Force file content only (DSYNC). */
        DATA,
        /** Force file content and metadata (SYNC). */
        FULL
    }

    /** An action to run when the channel is closed. */
    interface CloseAction {
        /** Runs the action. */
        void run() throws IOException;
    }

    private final CipherFile file;
    private final boolean readable;
    private final boolean writable;
    private final Sync sync;
    private final CloseAction closeAction;
    private long position;
    private boolean open = true;

    GocryptFsFileChannel(CipherFile file, boolean readable, boolean writable,
                         long initialPosition, Sync sync, CloseAction closeAction) {
        this.file = file;
        this.readable = readable;
        this.writable = writable;
        this.position = initialPosition;
        this.sync = sync;
        this.closeAction = closeAction;
    }

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

    /** Forces pending updates according to the channel's sync mode. */
    private void force() throws IOException {
        if (sync == Sync.FULL) {
            file.force(true);
        } else if (sync == Sync.DATA) {
            file.force(false);
        }
    }

    @Override
    public long position() {
        return position;
    }

    @Override
    public SeekableByteChannel position(long newPosition) {
        if (newPosition < 0) {
            throw new IllegalArgumentException("negative position");
        }
        this.position = newPosition;
        return this;
    }

    @Override
    public long size() throws IOException {
        return file.plainSize();
    }

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

    @Override
    public boolean isOpen() {
        return open;
    }

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
