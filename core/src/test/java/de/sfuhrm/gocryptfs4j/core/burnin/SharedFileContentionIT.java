package de.sfuhrm.gocryptfs4j.core.burnin;

import de.sfuhrm.gocryptfs4j.core.BlockBufferedChannel;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.core.SharedCipherFile;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.CRC32;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Deterministic contention on a single file: disjoint range writes, concurrent
 * appends with self-describing records, and a rename while a handle is open.
 */
@Tag("burn-in")
class SharedFileContentionIT {

    /** Record magic for the append test. */
    private static final int MAGIC = 0x47434634;

    /** Record header size (magic, thread, sequence, payload length, checksum). */
    private static final int RECORD_HEADER = 20;

    @TempDir
    Path tmp;

    @Test
    void disjointRangeWritesAreNotLost() throws Exception {
        Path root = BurnInSupport.newRoot(tmp, "ranges");
        int threadCount = Math.max(4, Math.min(BurnInSupport.threads(), 16));
        int chunksPerThread = 8;
        int chunkSize = 1024;
        long seed = BurnInSupport.seed();
        byte[] expected = new byte[threadCount * chunksPerThread * chunkSize];
        Random content = new Random(seed);

        for (int i = 0; i < expected.length; i++) {
            expected[i] = (byte) content.nextInt();
        }

        try (PathCipherStore store = new PathCipherStore(root);
             GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD)) {
            fs.createFile("/ranges.bin");
            runConcurrently(threadCount, thread -> {
                for (int chunk = 0; chunk < chunksPerThread; chunk++) {
                    int offset = (thread * chunksPerThread + chunk) * chunkSize;
                    byte[] data = Arrays.copyOfRange(expected, offset, offset + chunkSize);
                    fs.write("/ranges.bin", offset, data);
                }
            });

            assertArrayEquals(expected, fs.readAll("/ranges.bin"));
        }

        assertArrayEquals(expected, BurnInSupport.readFresh(root, "/ranges.bin"));
    }

    @Test
    void concurrentAppendsKeepWholeRecords() throws Exception {
        Path root = BurnInSupport.newRoot(tmp, "append");
        appendScenario(root, false);
    }

    @Test
    void concurrentAppendsOnOneSharedHandleKeepWholeRecords() throws Exception {
        Path root = BurnInSupport.newRoot(tmp, "append-shared");
        appendScenario(root, true);
    }

    @Test
    void renameWhileWritingPreservesBothHalves() throws Exception {
        Path root = BurnInSupport.newRoot(tmp, "rename");
        byte[] first = BurnInSupport.randomBytes(new Random(BurnInSupport.seed()), 4096);
        byte[] second = BurnInSupport.randomBytes(new Random(BurnInSupport.seed() + 1), 3000);
        byte[] expected = BurnInSupport.concat(first, second);

        try (PathCipherStore store = new PathCipherStore(root);
             GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD)) {
            fs.createFile("/moving.bin");
            try (SharedCipherFile file = fs.openCipherFile("/moving.bin", true);
                 BlockBufferedChannel channel = file.newChannel(0, true)) {
                channel.write(ByteBuffer.wrap(first));
                channel.flush();
                fs.rename("/moving.bin", "/moved.bin", false);
                channel.write(ByteBuffer.wrap(second));
            }

            assertArrayEquals(expected, fs.readAll("/moved.bin"));
        }

        assertArrayEquals(expected, BurnInSupport.readFresh(root, "/moved.bin"));
    }

    private void appendScenario(Path root, boolean oneSharedHandle) throws Exception {
        int threadCount = Math.max(4, Math.min(BurnInSupport.threads(), 12));
        int recordsPerThread = 20;
        long seed = BurnInSupport.seed();

        try (PathCipherStore store = new PathCipherStore(root);
             GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD)) {
            fs.createFile("/append.bin");
            SharedCipherFile shared = oneSharedHandle
                    ? fs.openCipherFile("/append.bin", true) : null;
            try {
                AtomicReference<Throwable> failure = new AtomicReference<>();
                runConcurrently(threadCount, thread -> {
                    try {
                        SharedCipherFile own = oneSharedHandle
                                ? shared : fs.openCipherFile("/append.bin", true);
                        try (BlockBufferedChannel channel = own.newChannel(0, true)) {
                            Random random = BurnInSupport.random(seed, thread);
                            for (int sequence = 0; sequence < recordsPerThread; sequence++) {
                                byte[] record = record(thread, sequence, random);
                                channel.append(ByteBuffer.wrap(record));
                            }
                        } finally {
                            if (!oneSharedHandle) {
                                own.close();
                            }
                        }
                    } catch (Throwable t) {
                        failure.compareAndSet(null, t);
                        throw t;
                    }
                });
                assertNull(failure.get(), "append worker failed");
            } finally {
                if (shared != null) {
                    shared.close();
                }
            }
        }

        verifyRecords(BurnInSupport.readFresh(root, "/append.bin"),
                threadCount, recordsPerThread, seed);
    }

    private static byte[] record(int thread, int sequence, Random random) {
        int payloadLength = random.nextInt(400);
        byte[] payload = BurnInSupport.randomBytes(random, payloadLength);
        CRC32 crc = new CRC32();
        crc.update(payload);
        ByteBuffer buffer = ByteBuffer.allocate(RECORD_HEADER + payloadLength);
        buffer.putInt(MAGIC);
        buffer.putInt(thread);
        buffer.putInt(sequence);
        buffer.putInt(payloadLength);
        buffer.put(payload);
        buffer.putInt((int) crc.getValue());
        return buffer.array();
    }

    private static void verifyRecords(byte[] data, int threadCount, int recordsPerThread,
                                      long seed) {
        int[] nextSequence = new int[threadCount];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int records = 0;
        while (buffer.hasRemaining()) {
            assertTrue(buffer.remaining() >= RECORD_HEADER,
                    "truncated append record header at offset " + buffer.position());
            int magic = buffer.getInt();
            assertEquals(MAGIC, magic, "interleaved or torn append record");
            int thread = buffer.getInt();
            int sequence = buffer.getInt();
            int payloadLength = buffer.getInt();
            assertTrue(thread >= 0 && thread < threadCount, "bad thread id in append record");
            assertTrue(payloadLength >= 0 && payloadLength <= 400,
                    "bad payload length in append record");
            assertTrue(buffer.remaining() >= payloadLength + 4,
                    "truncated append record payload at offset " + buffer.position());
            byte[] payload = new byte[payloadLength];
            buffer.get(payload);
            int expectedChecksum = buffer.getInt();
            CRC32 crc = new CRC32();
            crc.update(payload);
            assertEquals((int) crc.getValue(), expectedChecksum,
                    "append record payload corrupted");

            Random expectedRandom = BurnInSupport.random(seed, thread);
            for (int i = 0; i < sequence; i++) {
                BurnInSupport.randomBytes(expectedRandom, expectedRandom.nextInt(400));
            }
            byte[] expectedPayload = BurnInSupport.randomBytes(expectedRandom,
                    expectedRandom.nextInt(400));
            assertArrayEquals(expectedPayload, payload, "append record order/payload mismatch");

            assertEquals(nextSequence[thread]++, sequence,
                    "append records of one thread are out of order");
            records++;
        }
        assertEquals(threadCount * recordsPerThread, records,
                "lost or duplicated append records");
        for (int thread = 0; thread < threadCount; thread++) {
            assertEquals(recordsPerThread, nextSequence[thread],
                    "missing append records for thread " + thread);
        }
    }

    private interface ConcurrentTask {
        void run(int thread) throws Exception;
    }

    private static void runConcurrently(int threadCount, ConcurrentTask task) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        List<Future<?>> futures = new ArrayList<>();
        CountDownLatch start = new CountDownLatch(1);
        try {
            for (int i = 0; i < threadCount; i++) {
                int thread = i;
                futures.add(pool.submit(() -> {
                    start.await();
                    task.run(thread);
                    return null;
                }));
            }
            start.countDown();
            BurnInSupport.awaitAll(futures,
                    TimeUnit.SECONDS.toNanos(BurnInSupport.seconds() + 60));
        } finally {
            pool.shutdownNow();
        }
    }
}
