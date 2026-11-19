package de.sfuhrm.gocryptfs4j.core.burnin;

import de.sfuhrm.gocryptfs4j.core.BlockBufferedChannel;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.core.SharedCipherFile;
import de.sfuhrm.gocryptfs4j.core.SyncPolicy;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Verifies buffer and cache coherence for every {@link SyncPolicy}, including
 * block-boundary sizes, sparse writes, unaligned reads and truncation.
 */
@Tag("burn-in")
class BufferCoherenceIT {

    /** Sizes around the 4 KiB block size used by the format. */
    private static final int[] BOUNDARY_SIZES = {
            0, 1, 4095, 4096, 4097, 8191, 8192, 8193
    };

    @TempDir
    Path tmp;

    @Test
    void visibilityMatchesSyncPolicyForBoundarySizes() throws Exception {
        Random random = new Random(BurnInSupport.seed());
        for (SyncPolicy policy : SyncPolicy.values()) {
            for (int size : BOUNDARY_SIZES) {
                Path root = BurnInSupport.newRoot(tmp, policy + "-" + size);
                byte[] data = BurnInSupport.randomBytes(random, size);
                try (PathCipherStore store = new PathCipherStore(root);
                     GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD, policy)) {
                    fs.createFile("/f.bin");

                    if (policy == SyncPolicy.NONE) {
                        try (SharedCipherFile handle = fs.openCipherFile("/f.bin", true)) {
                            fs.write("/f.bin", 0, data);
                            if (size == 1) {
                                assertArrayEquals(new byte[0],
                                        BurnInSupport.readFresh(root, "/f.bin"),
                                        "NONE must not publish before the last handle closes");
                            }
                        }
                    } else {
                        fs.write("/f.bin", 0, data);
                        assertArrayEquals(data, BurnInSupport.readFresh(root, "/f.bin"),
                                policy + " must publish a completed write");
                    }

                    assertArrayEquals(data, fs.readAll("/f.bin"));
                }

                assertArrayEquals(data, BurnInSupport.readFresh(root, "/f.bin"),
                        "content after close for " + policy + " size " + size);
            }
        }
    }

    @Test
    void sparseAndUnalignedAccessSurvivesReopen() throws Exception {
        Random random = new Random(BurnInSupport.seed() + 17);
        int offset = 2 * 4096 + 5;
        byte[] payload = BurnInSupport.randomBytes(random, 17);
        byte[] expected = new byte[offset + payload.length];
        System.arraycopy(payload, 0, expected, offset, payload.length);

        for (SyncPolicy policy : SyncPolicy.values()) {
            Path root = BurnInSupport.newRoot(tmp, "sparse-" + policy);
            try (PathCipherStore store = new PathCipherStore(root);
                 GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD, policy)) {
                fs.createFile("/sparse.bin");
                fs.write("/sparse.bin", offset, payload);
                assertArrayEquals(expected, fs.readAll("/sparse.bin"));

                try (SharedCipherFile file = fs.openCipherFile("/sparse.bin", false);
                     BlockBufferedChannel channel = file.newChannel(0, false)) {
                    assertEquals(expected.length, channel.size());
                    for (int i = 0; i < 100; i++) {
                        int position = random.nextInt(expected.length + 1);
                        int length = 1 + random.nextInt(300);
                        int available = Math.min(length, expected.length - position);
                        byte[] slice = BurnInSupport.readAt(channel, position, length);
                        assertArrayEquals(Arrays.copyOfRange(expected, position,
                                position + available), slice,
                                "unaligned read at " + position + " for " + policy);
                    }
                }
            }

            assertArrayEquals(expected, BurnInSupport.readFresh(root, "/sparse.bin"));
        }
    }

    @Test
    void truncateToEveryBoundarySurvivesReopen() throws Exception {
        Random random = new Random(BurnInSupport.seed() + 23);
        byte[] full = BurnInSupport.randomBytes(random, 2 * 4096 + 123);

        for (SyncPolicy policy : SyncPolicy.values()) {
            for (int target : BOUNDARY_SIZES) {
                Path root = BurnInSupport.newRoot(tmp, "trunc-" + policy + "-" + target);
                try (PathCipherStore store = new PathCipherStore(root);
                     GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD, policy)) {
                    fs.createFile("/t.bin");
                    fs.write("/t.bin", 0, full);
                    fs.truncate("/t.bin", target);
                    byte[] expected = Arrays.copyOf(full, target);
                    assertArrayEquals(expected, fs.readAll("/t.bin"));
                    assertEquals(target, fs.size("/t.bin"));
                }

                assertArrayEquals(Arrays.copyOf(full, target),
                        BurnInSupport.readFresh(root, "/t.bin"),
                        "truncate " + target + " for " + policy);
            }
        }
    }

    @Test
    void appendsAcrossBlockBoundariesStayContiguous() throws Exception {
        int[] appendSizes = {1, 4094, 1, 4095, 1, 4096, 1, 8191, 1};
        Random random = new Random(BurnInSupport.seed() + 29);

        for (SyncPolicy policy : SyncPolicy.values()) {
            Path root = BurnInSupport.newRoot(tmp, "append-" + policy);
            byte[] expected = new byte[0];
            try (PathCipherStore store = new PathCipherStore(root);
                 GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD, policy)) {
                fs.createFile("/a.bin");
                try (SharedCipherFile file = fs.openCipherFile("/a.bin", true);
                     BlockBufferedChannel channel = file.newChannel(0, true, policy)) {
                    for (int size : appendSizes) {
                        byte[] part = BurnInSupport.randomBytes(random, size);
                        channel.append(java.nio.ByteBuffer.wrap(part));
                        expected = BurnInSupport.concat(expected, part);
                        assertArrayEquals(expected, fs.readAll("/a.bin"));
                    }
                }
                assertArrayEquals(expected, fs.readAll("/a.bin"));
            }

            assertArrayEquals(expected, BurnInSupport.readFresh(root, "/a.bin"),
                    "append sequence for " + policy);
        }
    }

}
