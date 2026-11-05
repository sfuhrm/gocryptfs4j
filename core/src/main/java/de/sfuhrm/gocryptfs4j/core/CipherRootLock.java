package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A JVM-wide writer lock for a cipher store, combined with the store's own
 * {@link CipherStore#lockRoot()} capability.
 *
 * <p>The registry catches two writable filesystems on the same root inside one
 * JVM even when the backing store does not implement a file lock (for example a
 * wrapper around a local store). The store capability then extends the lock to
 * other processes or to the backend's own lease mechanism.</p>
 */
final class CipherRootLock implements AutoCloseable {

    /** The roots currently held by this JVM. */
    private static final ConcurrentHashMap<String, Boolean> HELD = new ConcurrentHashMap<>();

    /**
     * Stores with an empty root currently held by this JVM. A weak map keeps
     * independent in-memory stores independent without retaining them.
     */
    private static final Map<CipherStore, Boolean> HELD_BY_STORE =
            Collections.synchronizedMap(new WeakHashMap<>());

    /** The root key in {@link #HELD}, or {@code null} when the root has no key. */
    private final @Nullable String key;

    /** The store registered as a fallback for an empty root, or {@code null}. */
    private final @Nullable CipherStore storeIdentity;

    /** The store-level lock, or {@code null} when the store had no capability. */
    private final AutoCloseable storeLock;

    /** Guards {@link #close()} so it is idempotent. */
    private final AtomicBoolean closed = new AtomicBoolean();

    /**
     * Creates a combined lock.
     *
     * @param key           the root key in the registry, or {@code null}
     * @param storeIdentity the store registered for an empty root, or {@code null}
     * @param storeLock     the store-level lock, or {@code null}
     */
    private CipherRootLock(@Nullable String key, @Nullable CipherStore storeIdentity,
                           AutoCloseable storeLock) {
        this.key = key;
        this.storeIdentity = storeIdentity;
        this.storeLock = storeLock;
    }

    /**
     * Acquires the writer lock for {@code store}.
     *
     * <p>A store with an empty root (for example the in-memory store) is
     * registered by instance instead of by root name, because several
     * independent in-memory stores legitimately share the same empty root name.
     * The store's own capability still applies to it.</p>
     *
     * @param store the store to lock
     * @return the acquired lock
     * @throws IOException if the root is already locked or the store cannot
     *                     acquire its lock
     * @throws NullPointerException if {@code store} is {@code null}
     */
    static CipherRootLock acquire(CipherStore store) throws IOException {
        Objects.requireNonNull(store, "store");
        String root = store.root();
        String key = root == null || root.isEmpty() ? null : root;
        CipherStore storeIdentity = null;
        if (key != null) {
            if (HELD.putIfAbsent(key, Boolean.TRUE) != null) {
                throw new IOException("cipher directory is already open for writing: " + key);
            }
        } else {
            synchronized (HELD_BY_STORE) {
                if (HELD_BY_STORE.containsKey(store)) {
                    throw new IOException("cipher directory is already open for writing");
                }
                HELD_BY_STORE.put(store, Boolean.TRUE);
            }
            storeIdentity = store;
        }
        AutoCloseable storeLock = null;
        boolean ok = false;
        try {
            storeLock = store.lockRoot();
            CipherRootLock lock = new CipherRootLock(key, storeIdentity, storeLock);
            ok = true;
            return lock;
        } finally {
            if (!ok) {
                if (storeLock != null) {
                    try {
                        storeLock.close();
                    } catch (Exception ignored) {
                        // The acquisition failure is more important.
                    }
                }
                releaseRegistration(key, storeIdentity);
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        IOException failure = null;
        try {
            if (storeLock != null) {
                storeLock.close();
            }
        } catch (IOException e) {
            failure = e;
        } catch (Exception e) {
            failure = new IOException("failed to release cipher directory lock", e);
        } finally {
            releaseRegistration(key, storeIdentity);
        }
        if (failure != null) {
            throw failure;
        }
    }

    /**
     * Removes a registration from the appropriate JVM-wide registry.
     *
     * @param key           the root key, or {@code null}
     * @param storeIdentity the store identity, or {@code null}
     */
    private static void releaseRegistration(@Nullable String key,
                                            @Nullable CipherStore storeIdentity) {
        if (key != null) {
            HELD.remove(key);
        }
        if (storeIdentity != null) {
            synchronized (HELD_BY_STORE) {
                HELD_BY_STORE.remove(storeIdentity);
            }
        }
    }
}
