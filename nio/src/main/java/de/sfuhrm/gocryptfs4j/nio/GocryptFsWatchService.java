package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A polling {@link WatchService} for gocryptfs.
 *
 * <p>Since gocryptfs is a regular directory tree on disk, changes are detected
 * by periodically listing registered directories and diffing against the
 * previous snapshot. The service supports the {@code ENTRY_CREATE},
 * {@code ENTRY_DELETE}, {@code ENTRY_MODIFY} and {@code OVERFLOW} event kinds.</p>
 */
final class GocryptFsWatchService implements WatchService {

    /** An empty event kind array, used before a key is registered. */
    static final WatchEvent.Kind<?>[] NO_EVENTS = new WatchEvent.Kind<?>[0];

    /** The default interval, in milliseconds, between directory scans. */
    private static final long DEFAULT_POLL_INTERVAL_MILLIS = 1000L;

    /** The filesystem whose directories are watched. */
    private final GocryptFsFileSystem fs;

    /** The interval, in milliseconds, between directory scans. */
    private final long pollIntervalMillis;

    /** The registered keys, keyed by their directory. */
    private final Map<GocryptFsPath, GocryptFsWatchKey> keys = new HashMap<>();

    /** The keys that have pending events and await retrieval. */
    private final BlockingQueue<GocryptFsWatchKey> pending = new LinkedBlockingQueue<>();

    /** The scheduler that performs the periodic scans. */
    private final ScheduledExecutorService scheduler;

    /** Whether the service has been closed. */
    private volatile boolean closed;

    /**
     * Creates a service with the default poll interval.
     *
     * @param fs the filesystem whose directories are watched
     */
    GocryptFsWatchService(GocryptFsFileSystem fs) {
        this(fs, DEFAULT_POLL_INTERVAL_MILLIS);
    }

    /**
     * Creates a service with the given poll interval.
     *
     * @param fs                 the filesystem whose directories are watched
     * @param pollIntervalMillis the interval, in milliseconds, between directory scans
     */
    GocryptFsWatchService(GocryptFsFileSystem fs, long pollIntervalMillis) {
        this.fs = fs;
        this.pollIntervalMillis = pollIntervalMillis;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "gocryptfs-watch-service");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::scan, pollIntervalMillis, pollIntervalMillis,
                TimeUnit.MILLISECONDS);
    }

    /**
     * Returns the filesystem whose directories are watched.
     *
     * @return the watched filesystem
     */
    GocryptFsFileSystem fileSystem() {
        return fs;
    }

    /**
     * Returns whether the service has been closed.
     *
     * @return {@code true} if the service is closed
     */
    boolean isClosed() {
        return closed;
    }

    /**
     * Registers a directory for the given event kinds, reusing an existing key
     * if the directory is already registered.
     *
     * @param dir       the directory to register
     * @param events    the event kinds to watch for
     * @param modifiers the watch event modifiers; ignored
     * @return the watch key for the directory
     * @throws ClosedWatchServiceException if the service is closed
     * @throws IOException on filesystem errors while snapshotting the directory
     */
    WatchKey register(GocryptFsPath dir, WatchEvent.Kind<?>[] events,
                      WatchEvent.Modifier... modifiers) throws IOException {
        if (closed) {
            throw new ClosedWatchServiceException();
        }
        synchronized (keys) {
            GocryptFsWatchKey key = keys.get(dir);
            if (key == null) {
                key = new GocryptFsWatchKey(this, dir);
                keys.put(dir, key);
            }
            key.setEvents(events);
            key.snapshot();
            return key;
        }
    }

    /**
     * Removes a cancelled key.
     *
     * @param key the key to remove
     */
    void cancelKey(GocryptFsWatchKey key) {
        synchronized (keys) {
            keys.remove(key.directory());
        }
    }

    /**
     * Queues a key for retrieval, unless the service is closed.
     *
     * @param key the key to queue
     * @return {@code true} if the key was queued
     */
    boolean offer(GocryptFsWatchKey key) {
        return !closed && pending.offer(key);
    }

    /**
     * Scans all valid registered keys for changes. Called periodically by the
     * scheduler.
     */
    void scan() {
        List<GocryptFsWatchKey> snapshot;
        synchronized (keys) {
            snapshot = new ArrayList<>(keys.values());
        }
        for (GocryptFsWatchKey key : snapshot) {
            if (key.isValid()) {
                key.scan();
            }
        }
    }

    /**
     * Retrieves and removes the next key with pending events, or returns
     * {@code null} if none is available.
     *
     * @return the next key, or {@code null}
     * @throws ClosedWatchServiceException if the service is closed
     */
    @Override
    public WatchKey poll() {
        if (closed) {
            throw new ClosedWatchServiceException();
        }
        return pending.poll();
    }

    /**
     * Retrieves and removes the next key with pending events, waiting up to the
     * given timeout.
     *
     * @param timeout the maximum time to wait
     * @param unit    the time unit of the timeout
     * @return the next key, or {@code null} if the timeout elapses
     * @throws ClosedWatchServiceException if the service is closed
     * @throws InterruptedException if interrupted while waiting
     */
    @Override
    public WatchKey poll(long timeout, TimeUnit unit) throws InterruptedException {
        if (closed) {
            throw new ClosedWatchServiceException();
        }
        return pending.poll(timeout, unit);
    }

    /**
     * Retrieves and removes the next key with pending events, waiting
     * indefinitely until one is available.
     *
     * @return the next key
     * @throws ClosedWatchServiceException if the service is closed
     * @throws InterruptedException if interrupted while waiting
     */
    @Override
    public WatchKey take() throws InterruptedException {
        if (closed) {
            throw new ClosedWatchServiceException();
        }
        while (!closed) {
            GocryptFsWatchKey key = pending.poll(500L, TimeUnit.MILLISECONDS);
            if (key != null) {
                return key;
            }
        }
        throw new ClosedWatchServiceException();
    }

    /**
     * Closes the service, invalidates all keys and stops the scheduler. Closing
     * an already-closed service has no effect.
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        List<GocryptFsWatchKey> snapshot;
        synchronized (keys) {
            snapshot = new ArrayList<>(keys.values());
            keys.clear();
        }
        for (GocryptFsWatchKey key : snapshot) {
            key.invalidate();
        }
        scheduler.shutdownNow();
    }
}
