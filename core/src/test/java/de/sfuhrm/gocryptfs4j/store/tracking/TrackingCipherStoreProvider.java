package de.sfuhrm.gocryptfs4j.store.tracking;

import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.CipherStoreProvider;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A test-only {@link CipherStoreProvider} for the {@code tracking} URI scheme
 * that records every store it creates, so a test can assert whether ownership
 * caused a store to be closed. A test may also inject the store to hand out on
 * the next call via {@link #setNext(TrackingCipherStore)}.
 */
public final class TrackingCipherStoreProvider implements CipherStoreProvider {

    private static final List<TrackingCipherStore> CREATED = new CopyOnWriteArrayList<>();

    private static volatile TrackingCipherStore next;

    static void setNext(TrackingCipherStore store) {
        next = store;
    }

    static List<TrackingCipherStore> created() {
        return CREATED;
    }

    static void reset() {
        CREATED.clear();
        next = null;
    }

    @Override
    public String scheme() {
        return "tracking";
    }

    @Override
    public CipherStore newStore(URI uri, Map<String, ?> env) {
        TrackingCipherStore store = next != null ? next : new TrackingCipherStore();
        next = null;
        CREATED.add(store);
        return store;
    }
}
