package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.DirectorySnapshot;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.Watchable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link WatchKey} for a single registered gocryptfs directory.
 *
 * <p>Changes are detected by comparing a ciphertext snapshot of the directory
 * taken when the key was registered (or last reset) with the directory contents
 * on each scan. Only the names of entries that actually changed are decrypted.
 * Pending events are held in a queue until they are retrieved.</p>
 */
final class GocryptFsWatchKey implements WatchKey {

    /**
     * The maximum number of queued events. Beyond this the queue is replaced by
     * a single {@code OVERFLOW} event, matching the approximate limit the JDK
     * watch services use.
     */
    private static final int MAX_PENDING_EVENTS = 512;

    /** The key used to coalesce {@code OVERFLOW} events. */
    private static final EventKey OVERFLOW_KEY =
            new EventKey(StandardWatchEventKinds.OVERFLOW, null);

    /** The service this key belongs to. */
    private final GocryptFsWatchService service;

    /** The watched directory. */
    private final GocryptFsPath dir;

    /** Guards the snapshot, the event queue and the signalling state. */
    private final Object lock = new Object();

    /** The event kinds this key is interested in. */
    private WatchEvent.Kind<?>[] events = GocryptFsWatchService.NO_EVENTS;

    /** The last known ciphertext state of the watched directory. */
    private @Nullable DirectorySnapshot snapshot;

    /** The pending events, coalesced by kind and path context. */
    private final Map<EventKey, WatchEvent<?>> queue = new LinkedHashMap<>();

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
     * Replaces the snapshot with the current ciphertext state of the directory.
     *
     * @throws IOException on filesystem errors
     */
    void snapshot() throws IOException {
        DirectorySnapshot current = service.fileSystem().core()
                .snapshotDirectory(dir.toString());
        synchronized (lock) {
            snapshot = current;
        }
    }

    /**
     * Returns whether this key is interested in the given event kind.
     *
     * @param kind the event kind
     * @return {@code true} if the kind is watched
     */
    private boolean wants(WatchEvent.Kind<?> kind) {
        for (WatchEvent.Kind<?> k : events) {
            if (k.equals(kind)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Compares the directory against the snapshot, queues the resulting events
     * and updates the snapshot. Only the names of changed entries are
     * decrypted. On a listing failure an {@code OVERFLOW} event is queued and
     * the key is cancelled.
     */
    void scan() {
        DirectorySnapshot current;
        try {
            current = service.fileSystem().core().snapshotDirectory(dir.toString());
        } catch (IOException e) {
            failScan();
            return;
        }

        boolean failed = false;
        synchronized (lock) {
            if (snapshot == null) {
                // No initial snapshot was taken (for example a scan raced the
                // registration). Adopt the current state without emitting
                // create events for entries that already existed.
                snapshot = current;
                return;
            }

            List<DirectorySnapshot.Change> changes = Collections.emptyList();
            try {
                changes = current.changesSince(snapshot);
            } catch (IOException e) {
                failed = true;
            }
            if (!failed) {
                snapshot = current;
                for (DirectorySnapshot.Change change : changes) {
                    WatchEvent.Kind<?> kind = kindOf(change.kind());
                    if (wants(kind)) {
                        enqueueLocked(event(kind, change.plainName()));
                    }
                }
            }
        }
        if (failed) {
            failScan();
        }
    }

    /**
     * Maps a snapshot change kind to a watch event kind.
     *
     * @param kind the change kind
     * @return the corresponding watch event kind
     */
    private static WatchEvent.Kind<?> kindOf(DirectorySnapshot.ChangeKind kind) {
        switch (kind) {
            case CREATED:
                return StandardWatchEventKinds.ENTRY_CREATE;
            case MODIFIED:
                return StandardWatchEventKinds.ENTRY_MODIFY;
            case DELETED:
                return StandardWatchEventKinds.ENTRY_DELETE;
            default:
                throw new AssertionError("unknown change kind: " + kind);
        }
    }

    /**
     * Queues an {@code OVERFLOW} event and cancels the key after a failed scan.
     */
    private void failScan() {
        enqueue(StandardWatchEventKinds.OVERFLOW, null);
        cancel();
    }

    /**
     * Adds a single event to the queue and signals the key.
     *
     * @param kind the event kind
     * @param name the affected entry name, or {@code null}
     */
    private void enqueue(WatchEvent.Kind<?> kind, @Nullable String name) {
        synchronized (lock) {
            enqueueLocked(event(kind, name));
        }
    }

    /**
     * Adds an event to the queue, coalescing duplicates and replacing the queue
     * with a single {@code OVERFLOW} event when it grows too large. The caller
     * must hold {@link #lock}.
     *
     * @param newEvent the event to add
     */
    private void enqueueLocked(WatchEvent<?> newEvent) {
        if (queue.containsKey(OVERFLOW_KEY)) {
            // Once overflowed, everything else is already considered lost.
            return;
        }
        EventKey key = new EventKey(newEvent.kind(), newEvent.context());
        if (key.equals(OVERFLOW_KEY)) {
            queue.clear();
            queue.put(OVERFLOW_KEY, newEvent);
            signal();
            return;
        }
        if (queue.containsKey(key)) {
            return;
        }
        if (queue.size() >= MAX_PENDING_EVENTS) {
            queue.clear();
            queue.put(OVERFLOW_KEY, event(StandardWatchEventKinds.OVERFLOW, null));
            signal();
            return;
        }
        queue.put(key, newEvent);
        signal();
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
    private WatchEvent<Path> event(WatchEvent.Kind<?> kind, @Nullable String name) {
        @Nullable Path context = name == null ? null : dir.resolve(name);
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
            public @Nullable Path context() {
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
            List<WatchEvent<?>> result = new ArrayList<>(queue.values());
            queue.clear();
            return result;
        }
    }

    /**
     * Resets the key, clearing the signalled state so that further events
     * signal the key again.
     *
     * <p>If events were queued while the key was still signalled, the key is
     * re-offered so those events are not stranded. The directory snapshot is
     * intentionally left untouched: {@link #scan()} updates it, and taking a
     * fresh snapshot here would discard changes made since the last scan.</p>
     *
     * @return {@code true} if the key was reset, {@code false} if it is no
     *         longer valid
     */
    @Override
    public boolean reset() {
        synchronized (lock) {
            if (!valid || service.isClosed()) {
                valid = false;
                return false;
            }
            signalled = false;
            if (!queue.isEmpty()) {
                signal();
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
     * The identity of a queued event: its kind and path context.
     */
    private static final class EventKey {

        /** The event kind. */
        private final WatchEvent.Kind<?> kind;

        /** The event context, or {@code null}. */
        private final @Nullable Object context;

        /**
         * Creates an event key.
         *
         * @param kind    the event kind
         * @param context the event context, or {@code null}
         */
        EventKey(WatchEvent.Kind<?> kind, @Nullable Object context) {
            this.kind = kind;
            this.context = context;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof EventKey)) {
                return false;
            }
            EventKey that = (EventKey) o;
            return kind.equals(that.kind) && Objects.equals(context, that.context);
        }

        @Override
        public int hashCode() {
            return Objects.hash(kind, context);
        }
    }
}
