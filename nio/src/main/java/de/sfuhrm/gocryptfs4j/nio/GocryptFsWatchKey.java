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
 */
final class GocryptFsWatchKey implements WatchKey {

    private final GocryptFsWatchService service;
    private final GocryptFsPath dir;
    private final Object lock = new Object();

    private WatchEvent.Kind<?>[] events = GocryptFsWatchService.NO_EVENTS;
    private Map<String, SnapshotEntry> snapshot = Collections.emptyMap();
    private final Deque<WatchEvent<?>> queue = new ArrayDeque<>();
    private volatile boolean valid = true;
    private volatile boolean signalled;

    GocryptFsWatchKey(GocryptFsWatchService service, GocryptFsPath dir) {
        this.service = service;
        this.dir = dir;
    }

    GocryptFsPath directory() {
        return dir;
    }

    void setEvents(WatchEvent.Kind<?>[] events) {
        this.events = events.clone();
    }

    void snapshot() throws IOException {
        this.snapshot = listSnapshot();
    }

    private Map<String, SnapshotEntry> listSnapshot() throws IOException {
        Map<String, SnapshotEntry> map = new HashMap<>();
        for (DirEntry e : service.fileSystem().core().list(dir.toString())) {
            map.put(e.plainName(), new SnapshotEntry(e.kind(), e.size(), e.lastModifiedTime()));
        }
        return map;
    }

    private boolean wants(WatchEvent.Kind<?> kind) {
        for (WatchEvent.Kind<?> k : events) {
            if (k == kind) {
                return true;
            }
        }
        return false;
    }

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

    private void enqueue(WatchEvent.Kind<?> kind, String name) {
        synchronized (lock) {
            queue.add(event(kind, name));
            signal();
        }
    }

    private void signal() {
        if (!signalled) {
            signalled = true;
            service.offer(this);
        }
    }

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

    @Override
    public boolean isValid() {
        return valid;
    }

    @Override
    public List<WatchEvent<?>> pollEvents() {
        synchronized (lock) {
            List<WatchEvent<?>> result = new ArrayList<>(queue);
            queue.clear();
            return result;
        }
    }

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

    @Override
    public Watchable watchable() {
        return dir;
    }

    void invalidate() {
        valid = false;
    }

    /** A single entry snapshot used to detect changes between scans. */
    private static final class SnapshotEntry {
        private final DirEntry.Kind kind;
        private final long size;
        private final FileTime lastModifiedTime;

        SnapshotEntry(DirEntry.Kind kind, long size, FileTime lastModifiedTime) {
            this.kind = kind;
            this.size = size;
            this.lastModifiedTime = lastModifiedTime;
        }

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

        @Override
        public int hashCode() {
            return Objects.hash(kind, size, lastModifiedTime);
        }
    }
}
