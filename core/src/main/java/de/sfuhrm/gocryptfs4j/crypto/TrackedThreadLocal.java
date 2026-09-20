package de.sfuhrm.gocryptfs4j.crypto;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * A {@link ThreadLocal} that remembers every per-thread value it has created so
 * that {@link #wipeAll(Consumer)} can clear all of them from a single thread.
 *
 * <p>A plain {@link ThreadLocal} can only be cleared by the thread owning a
 * value, so a {@code wipe()} called from one thread leaves keyed scratch
 * objects belonging to other threads alive. This class closes that gap by
 * tracking the created values in a map keyed weakly by the owning thread: a
 * single thread can clear them all, and values belonging to terminated threads
 * become eligible for garbage collection on their own.</p>
 *
 * @param <T> the type of the tracked per-thread value
 */
final class TrackedThreadLocal<T> {

    /** The backing thread-local that creates the values. */
    private final ThreadLocal<T> local;

    /** The values created so far, keyed weakly by the owning thread. */
    private final Map<Thread, T> values =
            Collections.synchronizedMap(new WeakHashMap<Thread, T>());

    /**
     * Creates a tracked thread-local.
     *
     * @param supplier creates the per-thread value on first use
     * @throws NullPointerException if {@code supplier} is {@code null}
     */
    TrackedThreadLocal(Supplier<? extends T> supplier) {
        Objects.requireNonNull(supplier, "supplier");
        this.local = ThreadLocal.withInitial(() -> {
            T value = supplier.get();
            values.put(Thread.currentThread(), value);
            return value;
        });
    }

    /**
     * Returns this thread's value, creating and tracking it if necessary.
     *
     * @return the per-thread value
     */
    T get() {
        return local.get();
    }

    /**
     * Passes every value created so far to {@code wipe}, then forgets them all
     * and drops the calling thread's value.
     *
     * <p>Values owned by other threads stay referenced by their thread-local
     * maps until those threads next access the value or terminate, but their
     * contents have already been cleared by {@code wipe}. Concurrent use of a
     * thread-local while it is being wiped is not supported.</p>
     *
     * @param wipe clears a single value
     * @throws NullPointerException if {@code wipe} is {@code null}
     */
    void wipeAll(Consumer<? super T> wipe) {
        Objects.requireNonNull(wipe, "wipe");
        synchronized (values) {
            for (T value : values.values()) {
                wipe.accept(value);
            }
            values.clear();
        }
        local.remove();
    }
}
