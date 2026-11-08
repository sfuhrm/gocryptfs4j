package de.sfuhrm.gocryptfs4j.core;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Guards channel I/O against a filesystem close and marks the filesystem as
 * closing so no new channel operation can start.
 *
 * <p>Every channel operation takes the {@link #readLock() read lock} for the
 * duration of the I/O. {@link #writeLock() Closing} takes the write lock once,
 * marks the guard closed and then flushes and wipes while no channel can touch
 * the file or the key material. Operations that start after the close has
 * begun acquire the read lock only after the close finishes, observe
 * {@link #isClosed()} and fail instead of using wiped keys.</p>
 */
final class ChannelGuard {

    /** Read-held by channel I/O, write-held while the filesystem closes. */
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    /** Whether the owning filesystem has begun closing. */
    private volatile boolean closed;

    /**
     * Returns the lock held by channel I/O.
     *
     * @return the read lock
     */
    Lock readLock() {
        return lock.readLock();
    }

    /**
     * Returns the lock held while the filesystem closes.
     *
     * @return the write lock
     */
    Lock writeLock() {
        return lock.writeLock();
    }

    /**
     * Returns whether the owning filesystem has begun closing.
     *
     * @return {@code true} if the filesystem is closing or closed
     */
    boolean isClosed() {
        return closed;
    }

    /**
     * Marks the filesystem as closing. Must be called while holding the
     * {@link #writeLock() write lock}.
     */
    void markClosed() {
        closed = true;
    }
}
