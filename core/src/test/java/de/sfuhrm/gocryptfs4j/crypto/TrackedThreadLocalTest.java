package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrackedThreadLocalTest {

    /** A mutable marker standing in for a keyed scratch object. */
    private static final class Scratch {
        /** Whether this scratch has been wiped. */
        private volatile boolean wiped;
    }

    @Test
    void valuesAreCreatedOncePerThread() {
        TrackedThreadLocal<Scratch> local = new TrackedThreadLocal<>(Scratch::new);
        assertSame(local.get(), local.get());
    }

    @Test
    void wipeAllClearsValuesOfOtherThreads() throws InterruptedException {
        TrackedThreadLocal<Scratch> local = new TrackedThreadLocal<>(Scratch::new);

        Scratch mine = local.get();
        AtomicReference<Scratch> other = new AtomicReference<>();
        Thread worker = new Thread(() -> other.set(local.get()));
        worker.start();
        worker.join();

        assertNotSame(mine, other.get());
        assertFalse(mine.wiped);
        assertFalse(other.get().wiped);

        local.wipeAll(s -> s.wiped = true);

        assertTrue(mine.wiped, "calling thread's value must be wiped");
        assertTrue(other.get().wiped, "other thread's value must be wiped too");
    }

    @Test
    void getAfterWipeAllCreatesFreshValue() {
        TrackedThreadLocal<Scratch> local = new TrackedThreadLocal<>(Scratch::new);
        Scratch first = local.get();

        local.wipeAll(s -> s.wiped = true);
        Scratch second = local.get();

        assertNotSame(first, second);
        assertFalse(second.wiped);
    }

    @Test
    void wipeAllIsIdempotentAndDoesNotResurrectValues() {
        TrackedThreadLocal<Scratch> local = new TrackedThreadLocal<>(Scratch::new);
        local.get();

        AtomicInteger wiped = new AtomicInteger();
        local.wipeAll(s -> {
            s.wiped = true;
            wiped.incrementAndGet();
        });
        local.wipeAll(s -> {
            s.wiped = true;
            wiped.incrementAndGet();
        });

        assertEquals(1, wiped.get());
    }
}
