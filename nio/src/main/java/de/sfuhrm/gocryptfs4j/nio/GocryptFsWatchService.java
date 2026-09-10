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

    static final WatchEvent.Kind<?>[] NO_EVENTS = new WatchEvent.Kind<?>[0];

    private static final long DEFAULT_POLL_INTERVAL_MILLIS = 1000L;

    private final GocryptFsFileSystem fs;
    private final long pollIntervalMillis;
    private final Map<GocryptFsPath, GocryptFsWatchKey> keys = new HashMap<>();
    private final BlockingQueue<GocryptFsWatchKey> pending = new LinkedBlockingQueue<>();
    private final ScheduledExecutorService scheduler;
    private volatile boolean closed;

    GocryptFsWatchService(GocryptFsFileSystem fs) {
        this(fs, DEFAULT_POLL_INTERVAL_MILLIS);
    }

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

    GocryptFsFileSystem fileSystem() {
        return fs;
    }

    boolean isClosed() {
        return closed;
    }

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

    void cancelKey(GocryptFsWatchKey key) {
        synchronized (keys) {
            keys.remove(key.directory());
        }
    }

    boolean offer(GocryptFsWatchKey key) {
        return !closed && pending.offer(key);
    }

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

    @Override
    public WatchKey poll() {
        if (closed) {
            throw new ClosedWatchServiceException();
        }
        return pending.poll();
    }

    @Override
    public WatchKey poll(long timeout, TimeUnit unit) throws InterruptedException {
        if (closed) {
            throw new ClosedWatchServiceException();
        }
        return pending.poll(timeout, unit);
    }

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
