package de.sfuhrm.gocryptfs4j.store.local;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * An exclusive, advisory lock for one local ciphertext root directory.
 *
 * <p>A lock is held both in a static JVM-wide registry, keyed by the
 * canonical root path, and in an advisory lock on a sibling lock file. The
 * registry is needed because an operating-system file lock acquired by the
 * same JVM is reported as an overlapping lock instead of as contention, and the
 * file lock extends the protection to other processes.</p>
 *
 * <p>The lock file lives next to, not inside, the ciphertext directory, so it
 * never appears as an entry in the encrypted tree and does not need to be
 * hidden from listings or from other implementations of the format. It is
 * intentionally not deleted on release: unlinking a lock file while another
 * process might still open the old inode would allow two writers to hold locks
 * on different inodes for the same path.</p>
 */
final class RootFileLock implements AutoCloseable {

    /** The roots currently locked by this JVM. */
    private static final ConcurrentHashMap<String, Boolean> JVM_LOCKS = new ConcurrentHashMap<>();

    /** The canonical root key in {@link #JVM_LOCKS}. */
    private final String key;

    /** The open channel of the lock file. */
    private final FileChannel channel;

    /** The advisory lock on the lock file. */
    private final FileLock fileLock;

    /** Guards {@link #close()} so it is idempotent. */
    private final AtomicBoolean closed = new AtomicBoolean();

    /**
     * Creates a lock handle.
     *
     * @param key      the canonical root key
     * @param channel  the open lock-file channel
     * @param fileLock the advisory lock
     */
    private RootFileLock(String key, FileChannel channel, FileLock fileLock) {
        this.key = key;
        this.channel = channel;
        this.fileLock = fileLock;
    }

    /**
     * Acquires the lock for a local ciphertext root.
     *
     * @param root the canonical ciphertext root directory
     * @return the acquired lock
     * @throws IOException if the root is already locked or the lock file cannot
     *                     be opened
     * @throws NullPointerException if {@code root} is {@code null}
     */
    static RootFileLock acquire(Path root) throws IOException {
        Objects.requireNonNull(root, "root");
        String key = root.toString();
        if (JVM_LOCKS.putIfAbsent(key, Boolean.TRUE) != null) {
            throw new IOException("cipher directory is already open for writing: " + key);
        }
        FileChannel channel = null;
        FileLock fileLock = null;
        boolean ok = false;
        try {
            Path lockFile = lockFile(root);
            channel = FileChannel.open(lockFile, StandardOpenOption.CREATE,
                    StandardOpenOption.READ, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS);
            try {
                fileLock = channel.tryLock();
            } catch (OverlappingFileLockException e) {
                throw new IOException("cipher directory is already open for writing: " + key, e);
            }
            if (fileLock == null) {
                throw new IOException("cipher directory is locked by another process: " + key);
            }
            RootFileLock lock = new RootFileLock(key, channel, fileLock);
            ok = true;
            return lock;
        } finally {
            if (!ok) {
                if (fileLock != null) {
                    try {
                        fileLock.release();
                    } catch (IOException ignored) {
                        // The channel is closed below.
                    }
                }
                if (channel != null) {
                    try {
                        channel.close();
                    } catch (IOException ignored) {
                        // The original failure is more important.
                    }
                }
                JVM_LOCKS.remove(key);
            }
        }
    }

    /**
     * Returns the lock file for a root. It is a hidden sibling of the cipher
     * directory, named after the directory so that two ciphertext directories in
     * the same parent do not share a lock. A filesystem root has no parent, so
     * its lock file lives inside it.
     *
     * @param root the canonical ciphertext root directory
     * @return the lock file path
     */
    private static Path lockFile(Path root) {
        Path parent = root.getParent();
        Path fileName = root.getFileName();
        if (parent == null || fileName == null) {
            return root.resolve(".gocryptfs.lock");
        }
        return parent.resolve("." + fileName + ".gocryptfs.lock");
    }

    @Override
    public void close() throws IOException {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        IOException failure = null;
        try {
            fileLock.release();
        } catch (IOException e) {
            failure = e;
        }
        try {
            channel.close();
        } catch (IOException e) {
            if (failure == null) {
                failure = e;
            } else {
                failure.addSuppressed(e);
            }
        } finally {
            JVM_LOCKS.remove(key);
        }
        if (failure != null) {
            throw failure;
        }
    }
}
