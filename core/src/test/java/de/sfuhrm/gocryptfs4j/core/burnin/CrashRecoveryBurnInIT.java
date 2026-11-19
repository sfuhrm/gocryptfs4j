package de.sfuhrm.gocryptfs4j.core.burnin;

import de.sfuhrm.gocryptfs4j.core.BlockBufferedChannel;
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
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Simulated crashes at the journal, data-write and force boundaries. The
 * contract checked here is that a reopen exposes either the old or the new
 * complete block, never a torn mixture, and that a journaled block is replayed.
 */
@Tag("burn-in")
class CrashRecoveryBurnInIT {

    /** One plaintext block, so a single journal record describes the change. */
    private static final int BLOCK = 4096;

    @TempDir
    Path tmp;

    @Test
    void crashBeforeForceLeavesOldOrNewBlock() throws Exception {
        Path root = BurnInSupport.newRoot(tmp, "force-crash");
        Random random = new Random(BurnInSupport.seed() + 53);
        byte[] content = BurnInSupport.randomBytes(random, BLOCK);
        createVaultWithFile(root, content);

        try (PathCipherStore pathStore = new PathCipherStore(root)) {
            ChaosCipherStore chaos = new ChaosCipherStore(pathStore, false);
            int iterations = Math.max(3, Math.min(10, (int) BurnInSupport.seconds()));

            for (int i = 0; i < iterations; i++) {
                byte[] next = BurnInSupport.randomBytes(random, BLOCK);
                GocryptFs writer = GocryptFs.open(chaos, BurnInSupport.PASSWORD);
                SharedCipherFile file = writer.openCipherFile("/f.bin", true);
                BlockBufferedChannel channel = file.newChannel(0, true, SyncPolicy.NONE);
                channel.write(ByteBuffer.wrap(next));
                chaos.crashOnNextForce();
                try {
                    channel.flush();
                } catch (IOException expected) {
                    // The simulated crash may surface as a failed flush.
                }
                assertTrue(chaos.isCrashed(), "the force crash was not triggered");
                // writer, file and channel are abandoned on purpose.
                releaseJvmRootLock(chaos.root());

                chaos.restart();
                GocryptFs verifier = GocryptFs.open(chaos, BurnInSupport.PASSWORD);
                try {
                    // A writable open is the documented recovery point for a
                    // journal left behind by a crashed process.
                    verifier.openCipherFile("/f.bin", true).close();
                    byte[] actual = verifier.readAll("/f.bin");
                    assertTrue(Arrays.equals(content, actual) || Arrays.equals(next, actual),
                            "reopen exposed a torn block after a force crash");
                    content = actual;
                } finally {
                    verifier.close();
                }
            }
        }
    }

    @Test
    void crashAfterJournalReplaysTheNewBlock() throws Exception {
        Path root = BurnInSupport.newRoot(tmp, "journal-crash");
        Random random = new Random(BurnInSupport.seed() + 59);
        byte[] content = BurnInSupport.randomBytes(random, BLOCK);
        createVaultWithFile(root, content);

        try (PathCipherStore pathStore = new PathCipherStore(root)) {
            ChaosCipherStore chaos = new ChaosCipherStore(pathStore, false);
            int iterations = Math.max(3, Math.min(10, (int) BurnInSupport.seconds()));

            for (int i = 0; i < iterations; i++) {
                byte[] next = BurnInSupport.randomBytes(random, BLOCK);
                GocryptFs writer = GocryptFs.open(chaos, BurnInSupport.PASSWORD);
                SharedCipherFile file = writer.openCipherFile("/f.bin", true);
                BlockBufferedChannel channel = file.newChannel(0, true, SyncPolicy.NONE);
                channel.write(ByteBuffer.wrap(next));
                chaos.crashAfterNextJournal();
                try {
                    channel.flush();
                } catch (IOException expected) {
                    // The simulated crash may surface as a failed flush.
                }
                assertTrue(chaos.isCrashed(), "the journal crash was not triggered");
                releaseJvmRootLock(chaos.root());

                chaos.restart();
                GocryptFs verifier = GocryptFs.open(chaos, BurnInSupport.PASSWORD);
                try {
                    verifier.openCipherFile("/f.bin", true).close();
                    assertArrayEquals(next, verifier.readAll("/f.bin"),
                            "a journaled complete block must be replayed");
                    content = next;
                } finally {
                    verifier.close();
                }
            }
        }

        assertArrayEquals(content, BurnInSupport.readFresh(root, "/f.bin"));
    }

    @Test
    void repeatedForceFailuresDoNotPoisonLaterAccess() throws Exception {
        Path root = BurnInSupport.newRoot(tmp, "force-retry");
        Random random = new Random(BurnInSupport.seed() + 61);
        byte[] content = BurnInSupport.randomBytes(random, BLOCK);
        createVaultWithFile(root, content);

        try (PathCipherStore pathStore = new PathCipherStore(root)) {
            ChaosCipherStore chaos = new ChaosCipherStore(pathStore, false);
            try (GocryptFs fs = GocryptFs.open(chaos, BurnInSupport.PASSWORD)) {
                for (int i = 0; i < 5; i++) {
                    byte[] next = BurnInSupport.randomBytes(random, BLOCK);
                    try (SharedCipherFile file = fs.openCipherFile("/f.bin", true);
                         BlockBufferedChannel channel =
                                 file.newChannel(0, true, SyncPolicy.NONE)) {
                        channel.write(ByteBuffer.wrap(next));
                        chaos.failForces(true);
                        boolean failed = false;
                        try {
                            channel.flush();
                        } catch (IOException expected) {
                            failed = true;
                        } finally {
                            chaos.failForces(false);
                        }
                        assertTrue(failed, "the injected force failure did not fire");
                        // Retry after the storage problem clears.
                        channel.flush();
                    }
                    assertArrayEquals(next, fs.readAll("/f.bin"));
                    content = next;
                }
            }
        }

        assertArrayEquals(content, BurnInSupport.readFresh(root, "/f.bin"));
    }

    /**
     * Emulates the JVM-wide part of a process crash. The production root lock
     * keeps a registry entry until {@code close()}; a dead process loses it
     * automatically, which a test that abandons an instance must do explicitly.
     */
    private static void releaseJvmRootLock(String rootKey) throws Exception {
        Class<?> type = Class.forName("de.sfuhrm.gocryptfs4j.core.CipherRootLock");
        java.lang.reflect.Field held = type.getDeclaredField("HELD");
        held.setAccessible(true);
        Object value = held.get(null);
        if (value instanceof java.util.Map) {
            ((java.util.Map<?, ?>) value).remove(rootKey);
        }
    }

    private static void createVaultWithFile(Path root, byte[] content) throws IOException {
        try (PathCipherStore store = new PathCipherStore(root);
             GocryptFs fs = GocryptFs.create(store, BurnInSupport.PASSWORD)) {
            fs.createFile("/f.bin");
            fs.write("/f.bin", 0, content);
        }
    }
}
