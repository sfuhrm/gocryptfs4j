package de.sfuhrm.gocryptfs4j.core.burnin;

import de.sfuhrm.gocryptfs4j.core.BlockBufferedChannel;
import de.sfuhrm.gocryptfs4j.core.DirEntry;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.core.SharedCipherFile;
import de.sfuhrm.gocryptfs4j.core.SyncPolicy;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Mixed concurrent workload. File ownership is partitioned so the expected
 * plaintext of every writer-owned file is deterministic; readers concurrently
 * verify a set of immutable files through the same instance and through fresh
 * read-only instances.
 */
@Tag("burn-in")
class ThreadingBurnInIT {

    /** Upper bound for a mutable file, keeping the test fast. */
    private static final int MAX_FILE_SIZE = 128 * 1024;

    @TempDir
    Path tmp;

    @Test
    void mixedWorkloadKeepsOracle() throws Exception {
        long seed = BurnInSupport.seed();
        Path root = BurnInSupport.newRoot(tmp, "vault");
        byte[] marker = BurnInSupport.randomBytes(new Random(seed ^ 0x5eedL), 32);
        Map<String, byte[]> oracle = new ConcurrentHashMap<>();
        int totalThreads = Math.max(4, BurnInSupport.threads());
        int writerCount = Math.max(2, totalThreads - Math.max(2, totalThreads / 4));
        int readerCount = Math.max(1, totalThreads - writerCount);
        List<String> immutableNames = new ArrayList<>();
        Map<String, byte[]> immutableContent = new HashMap<>();
        long deadline = BurnInSupport.deadlineNanos();

        try (PathCipherStore store = new PathCipherStore(root)) {
            try (GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD)) {
                fs.setSyncPolicy(SyncPolicy.ON_CLOSE);

                fs.createFile("/marker.bin");
                fs.write("/marker.bin", 0, marker);
                oracle.put("/marker.bin", marker);

                Random seedRandom = new Random(seed);
                for (int i = 0; i < 4; i++) {
                    String name = "/seed-" + i + ".bin";
                    byte[] content = BurnInSupport.randomBytes(seedRandom,
                            1000 + seedRandom.nextInt(20000));
                    fs.createFile(name);
                    fs.write(name, 0, content);
                    immutableNames.add(name);
                    immutableContent.put(name, content);
                    oracle.put(name, content);
                }

                BurnInSupport.runWorkers(writerCount + readerCount, worker -> {
                    if (worker < writerCount) {
                        runWriter(fs, root, oracle, worker, seed, deadline);
                    } else {
                        runReader(fs, root, immutableNames, immutableContent,
                                new Random(seed + 31L * worker), deadline);
                    }
                });
            }

            try (PathCipherStore readStore = new PathCipherStore(root);
                 GocryptFs fresh = GocryptFs.openReadOnly(readStore,
                         BurnInSupport.PASSWORD)) {
                Set<String> actualNames = new HashSet<>();
                for (DirEntry entry : fresh.list("/")) {
                    actualNames.add(entry.plainName());
                }
                Set<String> expectedNames = new HashSet<>();
                for (String name : oracle.keySet()) {
                    expectedNames.add(baseName(name));
                }
                assertEquals(expectedNames, actualNames,
                        "final directory listing differs from the oracle");
                for (Map.Entry<String, byte[]> entry : oracle.entrySet()) {
                    assertArrayEquals(entry.getValue(), fresh.readAll(entry.getKey()),
                            "wrong final content for " + entry.getKey());
                }
            }

            BurnInSupport.assertNoPlaintext(root, marker);
        }
    }

    private static void runWriter(GocryptFs fs, Path root, Map<String, byte[]> oracle,
                                  int worker, long seed, long deadline)
            throws Exception {
        Random random = BurnInSupport.random(seed, worker);
        String[] names = {
                "/w" + worker + "-f0.bin",
                "/w" + worker + "-f1.bin"
        };
        Map<String, byte[]> local = new HashMap<>();
        for (String name : names) {
            fs.createFile(name);
            local.put(name, new byte[0]);
            oracle.put(name, new byte[0]);
        }
        int renameCounter = 0;

        while (!BurnInSupport.expired(deadline)) {
            String name = names[random.nextInt(names.length)];
            byte[] current = local.get(name);
            if (current == null) {
                fs.createFile(name);
                current = new byte[0];
                local.put(name, current);
                oracle.put(name, current);
            }

            int choice = random.nextInt(100);
            if (choice < 50) {
                current = writeAt(fs, name, current, random);
                local.put(name, current);
                oracle.put(name, current);
            } else if (choice < 65) {
                current = append(fs, name, current, random);
                local.put(name, current);
                oracle.put(name, current);
            } else if (choice < 77) {
                int newSize = random.nextInt(Math.min(current.length, MAX_FILE_SIZE) + 1);
                fs.truncate(name, newSize);
                current = Arrays.copyOf(current, newSize);
                local.put(name, current);
                oracle.put(name, current);
            } else if (choice < 85) {
                assertEquals(current.length, fs.size(name));
                assertEquals(current.length, fs.stat(name).size());
            } else if (choice < 92) {
                assertArrayEquals(current, fs.readAll(name));
                try (SharedCipherFile file = fs.openCipherFile(name, false);
                     BlockBufferedChannel channel = file.newChannel(0, false)) {
                    assertArrayEquals(current, BurnInSupport.readAllChannel(channel));
                }
            } else if (choice < 97) {
                String target = "/w" + worker + "-r" + (renameCounter++) + ".bin";
                fs.rename(name, target, false);
                local.remove(name);
                local.put(target, current);
                oracle.remove(name);
                oracle.put(target, current);
                for (int i = 0; i < names.length; i++) {
                    if (names[i].equals(name)) {
                        names[i] = target;
                        break;
                    }
                }
                continue;
            } else {
                fs.delete(name);
                local.remove(name);
                oracle.remove(name);
                continue;
            }

            assertArrayEquals(local.get(name), fs.readAll(name),
                    "read after mutation differs for " + name);
            if (random.nextInt(10) == 0) {
                assertArrayEquals(local.get(name), BurnInSupport.readFresh(root, name),
                        "fresh read-only instance sees stale data for " + name);
            }
        }
    }

    private static byte[] writeAt(GocryptFs fs, String name, byte[] current, Random random)
            throws IOException {
        int length = 1 + random.nextInt(250);
        byte[] data = BurnInSupport.randomBytes(random, length);
        int limit = Math.min(current.length, MAX_FILE_SIZE);
        int offset = limit == 0 ? 0 : random.nextInt(limit + 32);
        int newLength = Math.max(current.length, offset + length);
        byte[] updated = Arrays.copyOf(current, newLength);
        System.arraycopy(data, 0, updated, offset, length);
        fs.write(name, offset, data);
        return updated;
    }

    private static byte[] append(GocryptFs fs, String name, byte[] current, Random random)
            throws IOException {
        byte[] data = BurnInSupport.randomBytes(random, 1 + random.nextInt(300));
        try (SharedCipherFile file = fs.openCipherFile(name, true);
             BlockBufferedChannel channel = file.newChannel(0, true)) {
            channel.append(ByteBuffer.wrap(data));
        }
        return BurnInSupport.concat(current, data);
    }

    private static String baseName(String path) {
        int slash = path.lastIndexOf('/');
        return slash < 0 ? path : path.substring(slash + 1);
    }

    private static void runReader(GocryptFs fs, Path root, List<String> names,
                                  Map<String, byte[]> content, Random random, long deadline)
            throws IOException {
        long iteration = 0;
        while (!BurnInSupport.expired(deadline)) {
            String name = names.get(random.nextInt(names.size()));
            byte[] expected = content.get(name);
            assertArrayEquals(expected, fs.readAll(name));
            assertEquals(expected.length, fs.size(name));
            assertEquals(expected.length, fs.stat(name).size());

            List<DirEntry> entries = fs.list("/");
            Set<String> listed = new HashSet<>();
            for (DirEntry entry : entries) {
                listed.add(entry.plainName());
            }
            for (String seedName : names) {
                assertTrue(listed.contains(baseName(seedName)),
                        "listing lost immutable file " + seedName);
            }
            fs.snapshotDirectory("/");

            if (iteration++ % 25 == 0) {
                assertArrayEquals(expected, BurnInSupport.readFresh(root, name));
            }
        }
    }
}
