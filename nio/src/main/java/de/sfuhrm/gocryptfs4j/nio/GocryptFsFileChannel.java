package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.fs.CipherFile;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

/** A {@link SeekableByteChannel} over an encrypted file, exposing plaintext. */
final class GocryptFsFileChannel implements SeekableByteChannel {

    private final CipherFile file;
    private final boolean writable;
    private long position;
    private boolean open = true;

    GocryptFsFileChannel(CipherFile file, boolean writable, long initialPosition) {
        this.file = file;
        this.writable = writable;
        this.position = initialPosition;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        int n = file.read(dst, position);
        if (n > 0) {
            position += n;
        }
        return n;
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        if (!writable) {
            throw new java.nio.channels.NonWritableChannelException();
        }
        int n = file.write(src, position);
        position += n;
        return n;
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
            throw new java.nio.channels.NonWritableChannelException();
        }
        file.truncate(size);
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
            file.close();
        }
    }
}
