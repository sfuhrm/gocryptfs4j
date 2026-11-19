package de.sfuhrm.gocryptfs4j.core.burnin;

import de.sfuhrm.gocryptfs4j.core.BlockBufferedChannel;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Shared configuration and helpers for the burn-in tests.
 */
final class BurnInSupport {

    /** Password used by every burn-in vault. */
    static final char[] PASSWORD = "burn-in".toCharArray();

    private BurnInSupport() {
    }

    /** Returns the configured run time in seconds. */
    static long seconds() {
        return Long.parseLong(System.getProperty("burnin.seconds", "5"));
    }

    /** Returns the configured worker thread count. */
    static int threads() {
        return Integer.parseInt(System.getProperty("burnin.threads", "8"));
    }

    /** Returns the configured master seed. */
    static long seed() {
        return Long.parseLong(System.getProperty("burnin.seed", "1"));
    }

    /** Returns a deadline the given number of seconds from now. */
    static long deadlineNanos() {
        return System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds());
    }

    /** Returns whether the deadline has passed. */
    static boolean expired(long deadline) {
        return System.nanoTime() >= deadline;
    }

    /** Returns a deterministic random generator for one worker. */
    static Random random(long seed, int worker) {
        return new Random(seed * 1_000_003L + worker * 7919L);
    }

    /** Returns {@code length} pseudo-random bytes. */
    static byte[] randomBytes(Random random, int length) {
        byte[] data = new byte[length];
        random.nextBytes(data);
        return data;
    }

    /** Creates a fresh ciphertext root below {@code parent}. */
    static Path newRoot(Path parent, String name) throws IOException {
        return Files.createDirectories(parent.resolve(name));
    }

    /** Reads a file through a completely fresh read-only filesystem instance. */
    static byte[] readFresh(Path root, String plainPath) throws IOException {
        try (PathCipherStore store = new PathCipherStore(root)) {
            try (GocryptFs fs = GocryptFs.openReadOnly(store, PASSWORD)) {
                return fs.readAll(plainPath);
            }
        }
    }

    /**
     * Fails if the plaintext marker occurs in any regular file below the
     * ciphertext root.
     */
    static void assertNoPlaintext(Path root, byte[] marker) throws IOException {
        List<Path> files = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(root)) {
            stream.filter(Files::isRegularFile).forEach(files::add);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
        for (Path file : files) {
            byte[] data = Files.readAllBytes(file);
            assertFalse(indexOf(data, marker) >= 0,
                    "plaintext marker leaked into ciphertext file " + file);
        }
    }

    /** Returns the first occurrence of {@code needle} in {@code haystack}, or -1. */
    static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** Reads a channel from position zero to EOF. */
    static byte[] readAllChannel(BlockBufferedChannel channel) throws IOException {
        channel.position(0);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        while (true) {
            int read = channel.read(buffer);
            if (read < 0) {
                return out.toByteArray();
            }
            out.write(buffer.array(), 0, read);
            buffer.clear();
        }
    }

    /** Reads up to {@code length} bytes at {@code position}; short only at EOF. */
    static byte[] readAt(BlockBufferedChannel channel, long position, int length)
            throws IOException {
        channel.position(position);
        ByteBuffer buffer = ByteBuffer.allocate(length);
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer);
            if (read < 0) {
                break;
            }
        }
        return Arrays.copyOf(buffer.array(), buffer.position());
    }

    /** Concatenates two byte arrays. */
    static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    /** A unit of work executed by one burn-in thread. */
    interface Worker {
        void run(int worker) throws Exception;
    }

    /**
     * Runs {@code threadCount} workers to completion and fails with a thread
     * dump if they do not finish within the configured grace period.
     */
    static void runWorkers(int threadCount, Worker worker) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threadCount, threadFactory());
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threadCount; i++) {
                final int workerId = i;
                Callable<Void> task = () -> {
                    worker.run(workerId);
                    return null;
                };
                futures.add(pool.submit(task));
            }
            awaitAll(futures, TimeUnit.SECONDS.toNanos(seconds() + 60));
        } finally {
            pool.shutdownNow();
        }
    }

    /** Waits for all futures, dumping all threads on timeout. */
    static void awaitAll(List<Future<?>> futures, long timeoutNanos) throws Exception {
        long end = System.nanoTime() + timeoutNanos;
        for (Future<?> future : futures) {
            long remaining = end - System.nanoTime();
            if (remaining <= 0) {
                dumpThreads();
                fail("burn-in workers did not finish within the timeout");
            }
            try {
                future.get(remaining, TimeUnit.NANOSECONDS);
            } catch (TimeoutException e) {
                dumpThreads();
                for (Future<?> other : futures) {
                    other.cancel(true);
                }
                throw new AssertionError("burn-in worker stalled (possible deadlock)", e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof Exception) {
                    throw (Exception) cause;
                }
                if (cause instanceof Error) {
                    throw (Error) cause;
                }
                throw new AssertionError(cause);
            }
        }
    }

    /** Prints every live thread stack, useful when a burn-in run stalls. */
    static void dumpThreads() {
        System.err.println("==== burn-in thread dump ====");
        for (java.util.Map.Entry<Thread, StackTraceElement[]> entry
                : Thread.getAllStackTraces().entrySet()) {
            System.err.println(entry.getKey());
            for (StackTraceElement element : entry.getValue()) {
                System.err.println("    at " + element);
            }
        }
    }

    private static ThreadFactory threadFactory() {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, "burn-in-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }
}
