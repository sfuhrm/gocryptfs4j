package de.sfuhrm.gocryptfs4j.core.burnin;

import de.sfuhrm.gocryptfs4j.core.DirEntry;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.core.SyncPolicy;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the root writer lock and coexistence of a writable instance with
 * multiple read-only instances over the same ciphertext directory.
 */
@Tag("burn-in")
class MultiInstanceLockIT {

    /** The internal lock file name used by {@code RootFileLock}. */
    private static final String LOCK_FILE = ".gocryptfs.lock";

    @TempDir
    Path tmp;

    @Test
    void onlyOneWritableInstanceWinsARace() throws Exception {
        Path root = BurnInSupport.newRoot(tmp, "race");
        createVault(root);
        int racers = Math.max(2, Math.min(BurnInSupport.threads(), 8));
        AtomicInteger successes = new AtomicInteger();
        List<GocryptFs> opened = java.util.Collections.synchronizedList(new ArrayList<>());
        List<PathCipherStore> openedStores =
                java.util.Collections.synchronizedList(new ArrayList<>());
        CountDownLatch ready = new CountDownLatch(racers);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(racers);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < racers; i++) {
                futures.add(pool.submit(() -> {
                    PathCipherStore store = new PathCipherStore(root);
                    ready.countDown();
                    start.await();
                    try {
                        GocryptFs fs = GocryptFs.open(store, BurnInSupport.PASSWORD);
                        opened.add(fs);
                        openedStores.add(store);
                        successes.incrementAndGet();
                    } catch (IOException expected) {
                        store.close();
                    }
                    return null;
                }));
            }
            assertTrue(ready.await(30, TimeUnit.SECONDS));
            start.countDown();
            BurnInSupport.awaitAll(futures,
                    TimeUnit.SECONDS.toNanos(BurnInSupport.seconds() + 60));
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, successes.get(), "exactly one writable instance must win");
        for (GocryptFs fs : opened) {
            fs.close();
        }
        for (PathCipherStore store : openedStores) {
            store.close();
        }
        assertFalse(Files.exists(root.resolve(LOCK_FILE)),
                "the lock file must be removed when the writer closes");

        try (PathCipherStore store = new PathCipherStore(root);
             GocryptFs fs = GocryptFs.open(store, BurnInSupport.PASSWORD)) {
            fs.createFile("/after-race.bin");
            assertTrue(fs.list("/").stream()
                    .map(DirEntry::plainName)
                    .anyMatch(name -> name.equals("after-race.bin")));
        }
    }

    @Test
    void readersCoexistWithWriterAndSeeCommittedData() throws Exception {
        Path root = BurnInSupport.newRoot(tmp, "readers");
        createVault(root);
        Random random = new Random(BurnInSupport.seed());
        byte[] seedContent = BurnInSupport.randomBytes(random, 32 * 1024);
        Map<String, byte[]> liveContent = new HashMap<>();
        int liveFiles = 8;
        for (int i = 0; i < liveFiles; i++) {
            liveContent.put("/live-" + i + ".bin", new byte[0]);
        }

        int readerCount = Math.min(3, Math.max(1, BurnInSupport.threads() - 1));
        long deadline = BurnInSupport.deadlineNanos();
        List<PathCipherStore> readerStores = new ArrayList<>();
        List<GocryptFs> readers = new ArrayList<>();

        try (PathCipherStore writerStore = new PathCipherStore(root);
             GocryptFs writer = GocryptFs.open(writerStore, BurnInSupport.PASSWORD)) {
            writer.setSyncPolicy(SyncPolicy.ON_CLOSE);
            writer.createFile("/seed.bin");
            writer.write("/seed.bin", 0, seedContent);
            for (String name : liveContent.keySet()) {
                writer.createFile(name);
            }

            try {
                for (int i = 0; i < readerCount; i++) {
                    PathCipherStore store = new PathCipherStore(root);
                    readerStores.add(store);
                    readers.add(GocryptFs.openReadOnly(store, BurnInSupport.PASSWORD));
                }

                BurnInSupport.runWorkers(readerCount + 1, worker -> {
                    if (worker == 0) {
                        writeContinuously(writer, liveContent, deadline);
                    } else {
                        readContinuously(readers.get(worker - 1), seedContent, deadline);
                    }
                });
            } finally {
                for (GocryptFs reader : readers) {
                    reader.close();
                }
                for (PathCipherStore store : readerStores) {
                    store.close();
                }
            }

            for (Map.Entry<String, byte[]> entry : liveContent.entrySet()) {
                assertArrayEquals(entry.getValue(), writer.readAll(entry.getKey()));
            }
        }

        assertArrayEquals(seedContent, BurnInSupport.readFresh(root, "/seed.bin"));
        for (Map.Entry<String, byte[]> entry : liveContent.entrySet()) {
            assertArrayEquals(entry.getValue(), BurnInSupport.readFresh(root, entry.getKey()));
        }
        assertFalse(Files.exists(root.resolve(LOCK_FILE)));
        assertFalse(Files.exists(tmp.resolve(LOCK_FILE)),
                "no lock file may be created next to the vault");
    }

    private static void createVault(Path root) throws IOException {
        try (PathCipherStore store = new PathCipherStore(root);
             GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD)) {
            // Just create the config and release the lock.
        }
    }

    private static void writeContinuously(GocryptFs writer, Map<String, byte[]> liveContent,
                                          long deadline) throws IOException {
        Random random = new Random(BurnInSupport.seed() + 41);
        int iteration = 0;
        while (!BurnInSupport.expired(deadline)) {
            String name = "/live-" + (iteration % liveContent.size()) + ".bin";
            byte[] data = BurnInSupport.randomBytes(random, 4096);
            writer.write(name, 0, data);
            liveContent.put(name, data);
            assertArrayEquals(data, writer.readAll(name));
            iteration++;
        }
    }

    private static void readContinuously(GocryptFs reader, byte[] seedContent, long deadline)
            throws IOException {
        while (!BurnInSupport.expired(deadline)) {
            assertArrayEquals(seedContent, reader.readAll("/seed.bin"));
            List<DirEntry> entries = reader.list("/");
            assertTrue(entries.stream().anyMatch(entry -> entry.plainName().equals("seed.bin")));
        }
    }
}
