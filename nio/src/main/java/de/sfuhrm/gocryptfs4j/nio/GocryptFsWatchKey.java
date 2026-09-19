package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.DirEntry;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.Watchable;
import java.nio.file.attribute.FileTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link WatchKey} for a single registered gocryptfs directory.
 *
 * <p>Changes are detected by comparing a snapshot of the directory taken when
 * the key was registered (or last reset) with the directory contents on each
 * scan. Pending events are held in a queue until they are retrieved.</p>
 */
final class GocryptFsWatchKey implements WatchKey {

    /** The service this key belongs to. */
    private final GocryptFsWatchService service;

    /** The watched directory. */
    private final GocryptFsPath dir;

    /** Guards the snapshot, the event queue and the signalling state. */
    private final Object lock = new Object();

    /** The event kinds this key is interested in. */
    private WatchEvent.Kind<?>[] events = GocryptFsWatchService.NO_EVENTS;

    /** The last known state of the watched directory. */
    private Map<String, SnapshotEntry> snapshot = Collections.emptyMap();

    /** The pending events. */
    private final Deque<WatchEvent<?>> queue = new ArrayDeque<>();

    /** Whether the key is valid. */
    private volatile boolean valid = true;

    /** Whether the key is currently queued in the service. */
    private volatile boolean signalled;

    /**
     * Creates a key.
     *
     * @param service the owning service
     * @param dir     the watched directory
     */
    GocryptFsWatchKey(GocryptFsWatchService service, GocryptFsPath dir) {
        this.service = service;
        this.dir = dir;
    }

    /**
     * Returns the watched directory.
     *
     * @return the watched directory
     */
    GocryptFsPath directory() {
        return dir;
    }

    /**
     * Sets the event kinds this key is interested in.
     *
     * @param events the event kinds
     */
    void setEvents(WatchEvent.Kind<?>[] events) {
        this.events = events.clone();
    }

    /**
     * Replaces the snapshot with the current state of the directory.
     *
     * @throws IOException on filesystem errors
     */
    void snapshot() throws IOException {
        this.snapshot = listSnapshot();
    }

    /**
     * Lists the watched directory as a map of entry name to snapshot.
     *
     * @return the current snapshot
     * @throws IOException on filesystem errors
     */
    private Map<String, SnapshotEntry> listSnapshot() throws IOException {
        Map<String, SnapshotEntry> map = new HashMap<>();
        for (DirEntry e : service.fileSystem().core().list(dir.toString())) {
            map.put(e.plainName(), new SnapshotEntry(e.kind(), e.size(), e.lastModifiedTime()));
        }
        return map;
    }

    /**
     * Returns whether this key is interested in the given event kind.
     *
     * @param kind the event kind
     * @return {@code true} if the kind is watched
     */
    private boolean wants(WatchEvent.Kind<?> kind) {
        for (WatchEvent.Kind<?> k : events) {
            if (k == kind) {
                return true;
            }
        }
        return false;
    }

    /**
     * Compares the directory against the snapshot, queues the resulting events
     * and updates the snapshot. On a listing failure an {@code OVERFLOW} event
     * is queued and the key is cancelled.
     */
    void scan() {
        Map<String, SnapshotEntry> current;
        try {
            current = listSnapshot();
        } catch (IOException e) {
            enqueue(StandardWatchEventKinds.OVERFLOW, null);
            cancel();
            return;
        }

        List<WatchEvent<?>> added = new ArrayList<>();
        synchronized (lock) {
            for (Map.Entry<String, SnapshotEntry> e : snapshot.entrySet()) {
                SnapshotEntry now = current.get(e.getKey());
                if (now == null) {
                    if (wants(StandardWatchEventKinds.ENTRY_DELETE)) {
                        added.add(event(StandardWatchEventKinds.ENTRY_DELETE, e.getKey()));
                    }
                } else if (!now.equals(e.getValue()) && wants(StandardWatchEventKinds.ENTRY_MODIFY)) {
                    added.add(event(StandardWatchEventKinds.ENTRY_MODIFY, e.getKey()));
                }
            }
            for (Map.Entry<String, SnapshotEntry> e : current.entrySet()) {
                if (!snapshot.containsKey(e.getKey())
                        && wants(StandardWatchEventKinds.ENTRY_CREATE)) {
                    added.add(event(StandardWatchEventKinds.ENTRY_CREATE, e.getKey()));
                }
            }
            snapshot = current;
            if (!added.isEmpty()) {
                queue.addAll(added);
                signal();
            }
        }
    }

    /**
     * Adds a single event to the queue and signals the key.
     *
     * @param kind the event kind
     * @param name the affected entry name, or {@code null}
     */
    private void enqueue(WatchEvent.Kind<?> kind, String name) {
        synchronized (lock) {
            queue.add(event(kind, name));
            signal();
        }
    }

    /**
     * Queues this key in the service, if it is not already queued.
     */
    private void signal() {
        if (!signalled) {
            signalled = true;
            service.offer(this);
        }
    }

    /**
     * Creates a watch event with a path context.
     *
     * @param kind the event kind
     * @param name the affected entry name, or {@code null} for no context
     * @return the watch event
     */
    @SuppressWarnings("unchecked")
    private WatchEvent<Path> event(WatchEvent.Kind<?> kind, String name) {
        Path context = name == null ? null : dir.resolve(name);
        return new WatchEvent<Path>() {
            @Override
            public WatchEvent.Kind<Path> kind() {
                return (WatchEvent.Kind<Path>) kind;
            }

            @Override
            public int count() {
                return 1;
            }

            @Override
            public Path context() {
                return context;
            }
        };
    }

    /**
     * Returns whether the key is valid.
     *
     * @return {@code true} if the key is valid
     */
    @Override
    public boolean isValid() {
        return valid;
    }

    /**
     * Retrieves and removes the pending events.
     *
     * @return the pending events
     */
    @Override
    public List<WatchEvent<?>> pollEvents() {
        synchronized (lock) {
            List<WatchEvent<?>> result = new ArrayList<>(queue);
            queue.clear();
            return result;
        }
    }

    /**
     * Resets the key, clearing the signalled state and taking a fresh snapshot.
     *
     * @return {@code true} if the key was reset, {@code false} if it is no
     *         longer valid or the snapshot could not be taken
     */
    @Override
    public boolean reset() {
        synchronized (lock) {
            if (!valid || service.isClosed()) {
                valid = false;
                return false;
            }
            signalled = false;
            try {
                snapshot = listSnapshot();
            } catch (IOException e) {
                cancel();
                return false;
            }
            return true;
        }
    }

    /**
     * Cancels the key and removes it from the service.
     */
    @Override
    public void cancel() {
        synchronized (lock) {
            if (!valid) {
                return;
            }
            valid = false;
        }
        service.cancelKey(this);
    }

    /**
     * Returns the watched directory.
     *
     * @return the watched directory
     */
    @Override
    public Watchable watchable() {
        return dir;
    }

    /**
     * Invalidates the key without notifying the service, used when the service
     * closes.
     */
    void invalidate() {
        valid = false;
    }

    /**
     * A single entry snapshot used to detect changes between scans.
     */
    private static final class SnapshotEntry {

        /** The entry kind. */
        private final DirEntry.Kind kind;

        /** The entry size. */
        private final long size;

        /** The entry last-modified time. */
        private final FileTime lastModifiedTime;

        /**
         * Creates a snapshot entry.
         *
         * @param kind             the entry kind
         * @param size             the entry size
         * @param lastModifiedTime the entry last-modified time
         */
        SnapshotEntry(DirEntry.Kind kind, long size, FileTime lastModifiedTime) {
            this.kind = kind;
            this.size = size;
            this.lastModifiedTime = lastModifiedTime;
        }

        /**
         * Compares this entry with another object.
         *
         * @param o the object to compare to
         * @return {@code true} if kind, size and last-modified time are equal
         */
        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof SnapshotEntry)) {
                return false;
            }
            SnapshotEntry that = (SnapshotEntry) o;
            return size == that.size && kind == that.kind
                    && lastModifiedTime.equals(that.lastModifiedTime);
        }

        /**
         * Returns a hash code consistent with {@link #equals(Object)}.
         *
         * @return the hash code
         */
        @Override
        public int hashCode() {
            return Objects.hash(kind, size, lastModifiedTime);
        }
    }
}
