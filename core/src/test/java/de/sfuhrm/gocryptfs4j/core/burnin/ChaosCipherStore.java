package de.sfuhrm.gocryptfs4j.core.burnin;

import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.AccessMode;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A {@link CipherStore} decorator that can fail individual I/O operations or
 * simulate a process crash at a chosen boundary.
 *
 * <p>It is used by the crash-recovery burn-in tests. A simulated crash refuses
 * all further operations and closes the channels that are still open, which
 * approximates a process that died without running any cleanup. The data that
 * was already handed to the delegate store remains, exactly like data in the
 * operating system page cache survives a process crash.</p>
 */
final class ChaosCipherStore implements CipherStore {

    /** The real store that receives all successful operations. */
    private final CipherStore delegate;

    /** Whether the delegate's root lock is used. */
    private final boolean rootLockEnabled;

    /** Whether a simulated crash has happened. */
    private final AtomicBoolean crashed = new AtomicBoolean();

    /** Whether the next channel force simulates a crash instead of forcing. */
    private final AtomicBoolean crashOnNextForce = new AtomicBoolean();

    /** Whether the next journal write is followed by a simulated crash. */
    private final AtomicBoolean crashAfterNextJournal = new AtomicBoolean();

    /** Whether channel forces fail with an ordinary {@link IOException}. */
    private volatile boolean failForces;

    /** Number of upcoming small writes that fail with an ordinary exception. */
    private final java.util.concurrent.atomic.AtomicInteger failSmallWrites =
            new java.util.concurrent.atomic.AtomicInteger();

    /** Channels currently open through this store. */
    private final Set<CipherChannel> channels = ConcurrentHashMap.newKeySet();

    /**
     * Creates a chaos store.
     *
     * @param delegate         the real store
     * @param rootLockEnabled  whether to forward {@link #lockRoot()}
     */
    ChaosCipherStore(CipherStore delegate, boolean rootLockEnabled) {
        this.delegate = delegate;
        this.rootLockEnabled = rootLockEnabled;
    }

    /** Makes the next channel force simulate a crash. */
    void crashOnNextForce() {
        crashOnNextForce.set(true);
    }

    /** Makes the next journal write followed by a simulated crash. */
    void crashAfterNextJournal() {
        crashAfterNextJournal.set(true);
    }

    /** Makes all channel forces fail until cleared. */
    void failForces(boolean value) {
        this.failForces = value;
    }

    /** Makes the next {@code count} small writes fail. */
    void failNextSmallWrites(int count) {
        failSmallWrites.set(count);
    }

    /** Returns whether a simulated crash has happened. */
    boolean isCrashed() {
        return crashed.get();
    }

    /**
     * Clears the crashed state and all injection flags after the old
     * filesystem instance has been abandoned. Open channels are already
     * closed.
     */
    void restart() {
        crashOnNextForce.set(false);
        crashAfterNextJournal.set(false);
        failForces = false;
        failSmallWrites.set(0);
        crashed.set(false);
    }

    /** Simulates a crash: refuse all I/O and close open channels. */
    void crashNow() {
        if (crashed.compareAndSet(false, true)) {
            for (CipherChannel channel : channels.toArray(new CipherChannel[0])) {
                try {
                    channel.close();
                } catch (IOException | RuntimeException ignored) {
                    // A crashing process does not report cleanup failures.
                }
            }
            channels.clear();
        }
    }

    private void enter() throws IOException {
        if (crashed.get()) {
            throw new IOException("simulated crash");
        }
    }

    private boolean consumeSmallWriteFailure() {
        while (true) {
            int current = failSmallWrites.get();
            if (current <= 0) {
                return false;
            }
            if (failSmallWrites.compareAndSet(current, current - 1)) {
                return true;
            }
        }
    }

    @Override
    public String root() {
        return delegate.root();
    }

    @Override
    public AutoCloseable lockRoot() throws IOException {
        if (!rootLockEnabled) {
            return () -> {
                // Crash tests reopen the same root after abandoning an instance.
            };
        }
        return delegate.lockRoot();
    }

    @Override
    public byte[] readSmall(String name, int maxBytes) throws IOException {
        enter();
        return delegate.readSmall(name, maxBytes);
    }

    @Override
    public void writeSmall(String name, byte[] data, boolean overwrite) throws IOException {
        enter();
        if (consumeSmallWriteFailure()) {
            throw new IOException("injected small-write failure");
        }
        delegate.writeSmall(name, data, overwrite);
    }

    @Override
    public void writeJournal(String name, byte[] data) throws IOException {
        enter();
        if (consumeSmallWriteFailure()) {
            throw new IOException("injected journal-write failure");
        }
        delegate.writeJournal(name, data);
        if (crashAfterNextJournal.compareAndSet(true, false)) {
            crashNow();
        }
    }

    @Override
    public void writeConfig(String name, byte[] data, boolean overwrite) throws IOException {
        enter();
        delegate.writeConfig(name, data, overwrite);
    }

    @Override
    public CipherNode stat(String name) throws IOException {
        enter();
        return delegate.stat(name);
    }

    @Override
    public List<CipherNode> list(String dir) throws IOException {
        enter();
        return delegate.list(dir);
    }

    @Override
    public void createFile(String name) throws IOException {
        enter();
        delegate.createFile(name);
    }

    @Override
    public void mkdir(String name) throws IOException {
        enter();
        delegate.mkdir(name);
    }

    @Override
    public void delete(String name) throws IOException {
        enter();
        delegate.delete(name);
    }

    @Override
    public void rename(String from, String to, boolean replaceExisting) throws IOException {
        enter();
        delegate.rename(from, to, replaceExisting);
    }

    @Override
    public void createSymlink(String name, String target) throws IOException {
        enter();
        delegate.createSymlink(name, target);
    }

    @Override
    public String readSymlink(String name) throws IOException {
        enter();
        return delegate.readSymlink(name);
    }

    @Override
    public void setTimes(String name, @Nullable FileTime lastModifiedTime,
                         @Nullable FileTime lastAccessTime, @Nullable FileTime creationTime)
            throws IOException {
        enter();
        delegate.setTimes(name, lastModifiedTime, lastAccessTime, creationTime);
    }

    @Override
    public CipherChannel open(String name, boolean writable) throws IOException {
        enter();
        CipherChannel channel = delegate.open(name, writable);
        Channel wrapper = new Channel(channel);
        channels.add(wrapper);
        return wrapper;
    }

    @Override
    public void checkAccess(String name, AccessMode... modes) throws IOException {
        enter();
        delegate.checkAccess(name, modes);
    }

    @Override
    public @Nullable PosixFileAttributes posixAttributes(String name) throws IOException {
        enter();
        return delegate.posixAttributes(name);
    }

    @Override
    public void setPosixPermissions(String name, Set<PosixFilePermission> permissions)
            throws IOException {
        enter();
        delegate.setPosixPermissions(name, permissions);
    }

    @Override
    public void setPosixOwner(String name, UserPrincipal owner) throws IOException {
        enter();
        delegate.setPosixOwner(name, owner);
    }

    @Override
    public void setPosixGroup(String name, GroupPrincipal group) throws IOException {
        enter();
        delegate.setPosixGroup(name, group);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }

    /** A channel that checks the crashed state and tracks its own lifetime. */
    private final class Channel implements CipherChannel {

        private final CipherChannel delegateChannel;

        Channel(CipherChannel delegateChannel) {
            this.delegateChannel = delegateChannel;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            enter();
            return delegateChannel.read(dst);
        }

        @Override
        public int write(ByteBuffer src) throws IOException {
            enter();
            return delegateChannel.write(src);
        }

        @Override
        public long position() throws IOException {
            enter();
            return delegateChannel.position();
        }

        @Override
        public CipherChannel position(long newPosition) throws IOException {
            enter();
            delegateChannel.position(newPosition);
            return this;
        }

        @Override
        public long size() throws IOException {
            enter();
            return delegateChannel.size();
        }

        @Override
        public CipherChannel truncate(long size) throws IOException {
            enter();
            delegateChannel.truncate(size);
            return this;
        }

        @Override
        public void force(boolean metaData) throws IOException {
            enter();
            if (crashOnNextForce.compareAndSet(true, false)) {
                crashNow();
                throw new IOException("simulated crash before force");
            }
            if (failForces) {
                throw new IOException("injected force failure");
            }
            delegateChannel.force(metaData);
        }

        @Override
        public boolean isOpen() {
            return !crashed.get() && delegateChannel.isOpen();
        }

        @Override
        public void close() throws IOException {
            channels.remove(this);
            delegateChannel.close();
        }
    }
}
