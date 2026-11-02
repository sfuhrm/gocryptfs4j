package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests {@link DirectoryManager} in isolation: per-directory IV handling and
 * ciphertext-directory listing.
 */
class DirectoryManagerTest {

    private static String repeat(char c, int n) {
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            sb.append(c);
        }
        return sb.toString();
    }

    private static boolean anyNonZero(byte[] a) {
        for (byte b : a) {
            if (b != 0) {
                return true;
            }
        }
        return false;
    }

    @Test
    void readDirIVIsAllZeroForPlaintext() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();

        byte[] iv = h.directoryManager.readDirIV(h.store.root());

        assertEquals(Constants.DIR_IV_LEN, iv.length);
        assertTrue(Arrays.equals(new byte[Constants.DIR_IV_LEN], iv));
    }

    @Test
    void readDirIVIsAllZeroForDeterministic() throws IOException {
        ManagerHarness h = ManagerHarness.deterministic();

        byte[] iv = h.directoryManager.readDirIV(h.store.root());

        assertEquals(Constants.DIR_IV_LEN, iv.length);
        assertTrue(Arrays.equals(new byte[Constants.DIR_IV_LEN], iv));
    }

    @Test
    void readDirIVReturnsRandomNonZeroIV() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();

        byte[] iv = h.directoryManager.readDirIV(h.store.root());

        assertEquals(Constants.DIR_IV_LEN, iv.length);
        assertTrue(anyNonZero(iv));
    }

    @Test
    void readDirIVCachesUntilInvalidated() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        byte[] first = h.directoryManager.readDirIV(h.store.root());

        byte[] changed = new byte[Constants.DIR_IV_LEN];
        Arrays.fill(changed, (byte) 0x5a);
        h.store.writeSmall(PathResolver.join(h.store.root(), Constants.DIR_IV_FILENAME),
                changed, true);

        assertArrayEquals(first, h.directoryManager.readDirIV(h.store.root()),
                "cached IV must survive an external rewrite");

        h.directoryManager.invalidateDirIvCache(h.store.root());
        assertArrayEquals(changed, h.directoryManager.readDirIV(h.store.root()));
    }

    @Test
    void readDirIVCreatesMissingDirIV() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.store.mkdir("sub");

        byte[] iv = h.directoryManager.readDirIV("sub");

        assertEquals(Constants.DIR_IV_LEN, iv.length);
        assertTrue(anyNonZero(iv));
        assertArrayEquals(iv, h.store.readSmall(
                PathResolver.join("sub", Constants.DIR_IV_FILENAME), Constants.DIR_IV_LEN));
    }

    @Test
    void readDirIVRejectsNonEmptyDirectoryWithoutDirIV() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.store.mkdir("sub");
        h.store.createFile("sub/f");

        assertThrows(IOException.class, () -> h.directoryManager.readDirIV("sub"));
    }

    @Test
    void listCipherDirDecryptsNamesAndSkipsControlFiles() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.mkdir("/dir");
        h.fileManager.createFile("/a.txt");
        h.fileManager.createFile("/dir/b.txt");

        byte[] iv = h.directoryManager.readDirIV(h.store.root());
        List<DirEntry> entries = h.directoryManager.listCipherDir(h.store.root(), iv);

        Set<String> names = entries.stream()
                .map(DirEntry::plainName)
                .collect(Collectors.toSet());
        assertEquals(new HashSet<>(Arrays.asList("dir", "a.txt")), names);

        DirEntry file = entries.stream()
                .filter(e -> e.plainName().equals("a.txt"))
                .findFirst()
                .orElseThrow(AssertionError::new);
        assertEquals(DirEntry.Kind.FILE, file.kind());

        DirEntry dir = entries.stream()
                .filter(e -> e.plainName().equals("dir"))
                .findFirst()
                .orElseThrow(AssertionError::new);
        assertEquals(DirEntry.Kind.DIRECTORY, dir.kind());
    }

    @Test
    void listCipherDirResolvesLongNamesAndSkipsSupportFile() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        String longName = repeat('a', 200);
        h.fileManager.createFile("/" + longName);

        byte[] iv = h.directoryManager.readDirIV(h.store.root());
        List<DirEntry> entries = h.directoryManager.listCipherDir(h.store.root(), iv);

        assertEquals(1, entries.size());
        assertEquals(longName, entries.get(0).plainName());
        assertEquals(DirEntry.Kind.FILE, entries.get(0).kind());
    }

    @Test
    void listCipherDirIncludesBackslashNames() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/a\\b");

        byte[] iv = h.directoryManager.readDirIV(h.store.root());
        List<DirEntry> entries = h.directoryManager.listCipherDir(h.store.root(), iv);

        assertEquals(1, entries.size());
        assertEquals("a\\b", entries.get(0).plainName());
    }

    @Test
    void listCipherDirIncludesDirivInPlaintextMode() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();
        h.fileManager.mkdir("/dir");
        h.fileManager.createFile("/dir/gocryptfs.diriv");

        String cipherPath = h.pathResolver.resolve("/dir").cipherPath;
        byte[] iv = h.directoryManager.readDirIV(cipherPath);
        List<DirEntry> entries = h.directoryManager.listCipherDir(cipherPath, iv);

        assertEquals(1, entries.size());
        assertEquals("gocryptfs.diriv", entries.get(0).plainName());
        assertEquals(DirEntry.Kind.FILE, entries.get(0).kind());
    }

    @Test
    void listCipherDirIncludesDirivInDeterministicMode() throws IOException {
        ManagerHarness h = ManagerHarness.deterministic();
        h.fileManager.mkdir("/dir");
        h.fileManager.createFile("/dir/gocryptfs.diriv");

        String cipherPath = h.pathResolver.resolve("/dir").cipherPath;
        byte[] iv = h.directoryManager.readDirIV(cipherPath);
        List<DirEntry> entries = h.directoryManager.listCipherDir(cipherPath, iv);

        assertEquals(1, entries.size());
        assertEquals("gocryptfs.diriv", entries.get(0).plainName());
        assertEquals(DirEntry.Kind.FILE, entries.get(0).kind());
    }

    @Test
    void listCipherDirReflectsUnflushedWriteBack() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/f.txt");

        try (SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true)) {
            // A single short block stays in the write-back buffer and is not yet
            // written through, but listing must still report its plaintext size.
            cf.write(ByteBuffer.wrap(new byte[100]), 0);

            byte[] iv = h.directoryManager.readDirIV(h.store.root());
            List<DirEntry> entries = h.directoryManager.listCipherDir(h.store.root(), iv);

            assertEquals(1, entries.size());
            assertEquals(100L, entries.get(0).size());
        }
    }

    @Test
    void listCipherDirSkipsLongNameWhoseContentDoesNotMatchItsHash() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        String nameA = repeat('a', 200);
        String nameB = repeat('b', 200);
        h.fileManager.createFile("/" + nameA);
        h.fileManager.createFile("/" + nameB);

        String cipherA = h.pathResolver.resolve("/" + nameA).cipherName;
        String cipherB = h.pathResolver.resolve("/" + nameB).cipherName;
        String fileA = PathResolver.join(h.store.root(), cipherA + Constants.LONG_NAME_SUFFIX);
        String fileB = PathResolver.join(h.store.root(), cipherB + Constants.LONG_NAME_SUFFIX);

        // Swap the two .name support files, so each content no longer hashes to
        // the hash embedded in its own file name.
        byte[] contentA = h.store.readSmall(fileA, Constants.LONG_NAME_CONTENT_MAX_SIZE);
        byte[] contentB = h.store.readSmall(fileB, Constants.LONG_NAME_CONTENT_MAX_SIZE);
        h.store.writeSmall(fileA, contentB, true);
        h.store.writeSmall(fileB, contentA, true);

        byte[] iv = h.directoryManager.readDirIV(h.store.root());
        assertTrue(h.directoryManager.listCipherDir(h.store.root(), iv).isEmpty());
    }
}
