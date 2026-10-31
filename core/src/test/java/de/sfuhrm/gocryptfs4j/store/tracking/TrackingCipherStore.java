package de.sfuhrm.gocryptfs4j.store.tracking;

import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.memory.MapCipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.file.attribute.FileTime;
import java.util.List;

/**
 * A test-only {@link CipherStore} that delegates to an in-memory store and
 * records whether {@link #close()} was called, so ownership can be asserted.
 */
final class TrackingCipherStore implements CipherStore {

    private final MapCipherStore delegate = new MapCipherStore();
    private boolean closed;

    boolean isClosed() {
        return closed;
    }

    @Override
    public String root() {
        return delegate.root();
    }

    @Override
    public byte[] readSmall(String name, int maxBytes) throws IOException {
        return delegate.readSmall(name, maxBytes);
    }

    @Override
    public void writeSmall(String name, byte[] data, boolean overwrite) throws IOException {
        delegate.writeSmall(name, data, overwrite);
    }

    @Override
    public CipherNode stat(String name) throws IOException {
        return delegate.stat(name);
    }

    @Override
    public List<CipherNode> list(String dir) throws IOException {
        return delegate.list(dir);
    }

    @Override
    public void createFile(String name) throws IOException {
        delegate.createFile(name);
    }

    @Override
    public void mkdir(String name) throws IOException {
        delegate.mkdir(name);
    }

    @Override
    public void delete(String name) throws IOException {
        delegate.delete(name);
    }

    @Override
    public void rename(String from, String to, boolean replaceExisting) throws IOException {
        delegate.rename(from, to, replaceExisting);
    }

    @Override
    public void createSymlink(String name, String target) throws IOException {
        delegate.createSymlink(name, target);
    }

    @Override
    public String readSymlink(String name) throws IOException {
        return delegate.readSymlink(name);
    }

    @Override
    public void setTimes(String name, @Nullable FileTime lastModifiedTime,
                         @Nullable FileTime lastAccessTime, @Nullable FileTime creationTime)
            throws IOException {
        delegate.setTimes(name, lastModifiedTime, lastAccessTime, creationTime);
    }

    @Override
    public CipherChannel open(String name, boolean writable) throws IOException {
        return delegate.open(name, writable);
    }

    @Override
    public void close() {
        closed = true;
        delegate.close();
    }
}
