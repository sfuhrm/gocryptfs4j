package de.sfuhrm.gocryptfs4j.core;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.NoSuchFileException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests {@link FileManager} in isolation: file content operations, create,
 * delete, rename and symlink handling.
 */
class FileManagerTest {

    @Test
    void createFileThenStatRoundTrips() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();

        h.fileManager.createFile("/f.txt");
        DirEntry e = h.fileManager.stat("/f.txt");

        assertEquals("f.txt", e.plainName());
        assertEquals(DirEntry.Kind.FILE, e.kind());
    }

    @Test
    void writeThenReadAllRoundTrips() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        byte[] data = "hello encrypted world".getBytes(StandardCharsets.UTF_8);

        h.fileManager.createFile("/f.txt");
        h.fileManager.write("/f.txt", 0, data);

        assertArrayEquals(data, h.fileManager.readAll("/f.txt"));
    }

    @Test
    void sizeAndTruncateReflectPlaintextLength() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        byte[] data = new byte[1000];
        Arrays.fill(data, (byte) 0x11);

        h.fileManager.createFile("/f.txt");
        h.fileManager.write("/f.txt", 0, data);
        assertEquals(1000, h.fileManager.size("/f.txt"));

        h.fileManager.truncate("/f.txt", 100);
        assertEquals(100, h.fileManager.size("/f.txt"));
    }

    @Test
    void statReflectsUnflushedWriteBack() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/f.txt");

        try (SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true)) {
            // A single short block stays in the write-back buffer and is not yet
            // written through, but stat must still report its plaintext size.
            cf.write(ByteBuffer.wrap(new byte[100]), 0);
            assertEquals(100L, h.fileManager.stat("/f.txt").size());
        }
    }

    @Test
    void mkdirCreatesDirectory() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();

        h.fileManager.mkdir("/dir");
        DirEntry e = h.fileManager.stat("/dir");

        assertEquals("dir", e.plainName());
        assertEquals(DirEntry.Kind.DIRECTORY, e.kind());
    }

    @Test
    void deleteRemovesFile() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/f.txt");

        h.fileManager.delete("/f.txt");

        assertThrows(NoSuchFileException.class, () -> h.fileManager.stat("/f.txt"));
    }

    @Test
    void deleteNonEmptyDirectoryThrows() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.mkdir("/dir");
        h.fileManager.createFile("/dir/f.txt");

        assertThrows(DirectoryNotEmptyException.class, () -> h.fileManager.delete("/dir"));
    }

    @Test
    void deleteEmptyDirectoryDeterministicNames() throws IOException {
        ManagerHarness h = ManagerHarness.deterministic();
        h.fileManager.mkdir("/dir");

        h.fileManager.delete("/dir");

        assertThrows(NoSuchFileException.class, () -> h.fileManager.stat("/dir"));
    }

    @Test
    void plaintextNamesDirivIsOrdinaryEntry() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();
        h.fileManager.mkdir("/dir");
        h.fileManager.createFile("/dir/gocryptfs.diriv");

        assertThrows(DirectoryNotEmptyException.class, () -> h.fileManager.delete("/dir"));
        assertEquals(DirEntry.Kind.FILE,
                h.fileManager.stat("/dir/gocryptfs.diriv").kind());

        h.fileManager.delete("/dir/gocryptfs.diriv");
        h.fileManager.delete("/dir");
        assertThrows(NoSuchFileException.class, () -> h.fileManager.stat("/dir"));
    }

    @Test
    void renameMovesFileWithoutChangingContent() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        byte[] data = "move me".getBytes(StandardCharsets.UTF_8);
        h.fileManager.createFile("/a.txt");
        h.fileManager.write("/a.txt", 0, data);

        h.fileManager.rename("/a.txt", "/b.txt", false);

        assertArrayEquals(data, h.fileManager.readAll("/b.txt"));
        assertThrows(NoSuchFileException.class, () -> h.fileManager.stat("/a.txt"));
    }

    @Test
    void createSymlinkEncryptsTargetAndReadsItBack() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createSymlink("/link", "/target");

        assertEquals("/target", h.fileManager.readSymlinkTarget("/link"));

        String cipherPath = h.pathResolver.resolve("/link").cipherPath;
        assertNotEquals("/target", h.store.readSymlink(cipherPath),
                "the stored symlink target must be encrypted");
    }

    @Test
    void symlinkTargetStoredUnencryptedForPlaintextNames() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();
        h.fileManager.createSymlink("/link", "/target");

        assertEquals("/target", h.fileManager.readSymlinkTarget("/link"));

        String cipherPath = h.pathResolver.resolve("/link").cipherPath;
        assertEquals("/target", h.store.readSymlink(cipherPath));
    }

    @Test
    void readSymlinkTargetWrapsBadBase64AsIoException() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        String cipherPath = h.pathResolver.resolve("/link").cipherPath;
        h.store.createSymlink(cipherPath, "!!!not-valid-base64!!!");

        assertThrows(IOException.class, () -> h.fileManager.readSymlinkTarget("/link"));
    }

    @Test
    void readSymlinkTargetWrapsShortCiphertextAsIoException() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        String cipherPath = h.pathResolver.resolve("/link").cipherPath;
        byte[] shortCipher = new byte[h.contentEnc.ivLen - 1];
        h.store.createSymlink(cipherPath, Base64.getUrlEncoder().encodeToString(shortCipher));

        assertThrows(IOException.class, () -> h.fileManager.readSymlinkTarget("/link"));
    }

    @Test
    void concurrentWritersToSameFileDoNotCorrupt() throws Exception {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/f.txt");

        int threads = 8;
        byte[] payload = new byte[(int) h.contentEnc.plainBS];
        Arrays.fill(payload, (byte) 0x5a);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier start = new CyclicBarrier(threads);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                final int offset = i * (int) h.contentEnc.plainBS;
                futures.add(pool.submit(() -> {
                    start.await();
                    h.fileManager.write("/f.txt", offset, payload);
                    return null;
                }));
            }
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdown();
        }

        byte[] read = h.fileManager.readAll("/f.txt");
        assertEquals(threads * payload.length, read.length);
        for (byte b : read) {
            assertEquals(0x5a, b, "concurrent writers must not corrupt the file");
        }
    }

    @Test
    void openHandlesShareOneCipherFile() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/f.txt");
        int block = (int) h.contentEnc.plainBS;

        byte[] first = new byte[block];
        Arrays.fill(first, (byte) 0x41);
        byte[] second = new byte[block];
        Arrays.fill(second, (byte) 0x42);

        SharedCipherFile h1 = h.fileManager.openCipherFile("/f.txt", true);
        try {
            // Buffer a write to block 0 without closing the handle.
            h1.write(ByteBuffer.wrap(first), 0);

            // A second handle writes the same block and closes, flushing it.
            try (SharedCipherFile h2 = h.fileManager.openCipherFile("/f.txt", true)) {
                h2.write(ByteBuffer.wrap(second), 0);
            }
        } finally {
            h1.close();
        }

        // The second handle's write must win; the first handle must not flush its
        // stale block over it when it closes.
        assertArrayEquals(second, h.fileManager.readAll("/f.txt"));
    }

    @Test
    void fileLocksShrinkOnDelete() throws Exception {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/f.txt");
        h.fileManager.write("/f.txt", 0, "x".getBytes(StandardCharsets.UTF_8));
        String cipherPath = h.pathResolver.resolve("/f.txt").cipherPath;

        assertTrue(fileLocks(h).containsKey(cipherPath));

        h.fileManager.delete("/f.txt");

        assertFalse(fileLocks(h).containsKey(cipherPath));
    }

    @Test
    void fileLockFollowsRename() throws Exception {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/a.txt");
        h.fileManager.write("/a.txt", 0, "x".getBytes(StandardCharsets.UTF_8));
        String from = h.pathResolver.resolve("/a.txt").cipherPath;
        String to = h.pathResolver.resolve("/b.txt").cipherPath;

        Object lock = fileLocks(h).get(from);
        assertNotNull(lock);

        h.fileManager.rename("/a.txt", "/b.txt", false);

        assertFalse(fileLocks(h).containsKey(from));
        assertSame(lock, fileLocks(h).get(to));
    }

    @Test
    void fileLockFollowsDirectoryRename() throws Exception {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.mkdir("/dir");
        h.fileManager.createFile("/dir/f.txt");
        h.fileManager.write("/dir/f.txt", 0, "x".getBytes(StandardCharsets.UTF_8));
        String from = h.pathResolver.resolve("/dir/f.txt").cipherPath;

        Object lock = fileLocks(h).get(from);
        assertNotNull(lock);

        h.fileManager.rename("/dir", "/dir2", false);

        String to = h.pathResolver.resolve("/dir2/f.txt").cipherPath;
        assertFalse(fileLocks(h).containsKey(from));
        assertSame(lock, fileLocks(h).get(to));
    }

    @Test
    void sharedFilesEntryRemovedOnDelete() throws Exception {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/f.txt");
        String cipherPath = h.pathResolver.resolve("/f.txt").cipherPath;

        try (SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true)) {
            assertTrue(sharedFiles(h).containsKey(cipherPath));
        }
        assertTrue(sharedFiles(h).containsKey(cipherPath),
                "the shared entry is retained while idle");

        h.fileManager.delete("/f.txt");
        assertFalse(sharedFiles(h).containsKey(cipherPath));
    }

    @Test
    void sharedFilesEntryMovedOnRename() throws Exception {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/a.txt");
        String from = h.pathResolver.resolve("/a.txt").cipherPath;
        String to = h.pathResolver.resolve("/b.txt").cipherPath;

        try (SharedCipherFile cf = h.fileManager.openCipherFile("/a.txt", true)) {
            assertTrue(sharedFiles(h).containsKey(from));
        }

        h.fileManager.rename("/a.txt", "/b.txt", false);

        assertFalse(sharedFiles(h).containsKey(from));
        assertTrue(sharedFiles(h).containsKey(to));
    }

    /**
     * Returns the private per-file lock map of a harness's file manager.
     *
     * @param h the harness
     * @return the lock map keyed by cipher path
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> fileLocks(ManagerHarness h) throws Exception {
        Field field = FileManager.class.getDeclaredField("fileLocks");
        field.setAccessible(true);
        return (Map<String, Object>) field.get(h.fileManager);
    }

    /**
     * Returns the private shared-file map of a harness's file manager.
     *
     * @param h the harness
     * @return the shared-file map keyed by cipher path
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> sharedFiles(ManagerHarness h) throws Exception {
        Field field = FileManager.class.getDeclaredField("sharedFiles");
        field.setAccessible(true);
        return (Map<String, Object>) field.get(h.fileManager);
    }
}
