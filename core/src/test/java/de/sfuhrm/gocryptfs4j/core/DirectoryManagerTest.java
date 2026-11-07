package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.memory.MapCipherStore;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.FileTime;
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
    void readDirIVDoesNotCreateMissingDirIV() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.store.mkdir("sub");

        byte[] iv = h.directoryManager.readDirIV("sub");

        assertEquals(Constants.DIR_IV_LEN, iv.length);
        assertTrue(anyNonZero(iv));
        assertThrows(NoSuchFileException.class, () -> h.store.readSmall(
                        PathResolver.join("sub", Constants.DIR_IV_FILENAME), Constants.DIR_IV_LEN),
                "a read must not create a missing diriv");
    }

    @Test
    void readDirIVOptInRepairCreatesMissingDirIV() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.store.mkdir("sub");

        byte[] iv = h.directoryManager.readDirIV("sub", true);

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
    void readDirIVDoesNotRepairOnInconsistentListing() throws IOException {
        ReadOnlyStore store = new ReadOnlyStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.store.mkdir("sub");
        store.listingConsistent = false;

        assertThrows(IOException.class, () -> h.directoryManager.readDirIV("sub", true));
        assertThrows(NoSuchFileException.class, () -> store.readSmall(
                        PathResolver.join("sub", Constants.DIR_IV_FILENAME), Constants.DIR_IV_LEN),
                "a repair must not mint and persist a diriv from a stale listing");
    }

    @Test
    void readDirIVListsEmptyOnReadOnlyStoreWithoutPersistingDirIV() throws IOException {
        ReadOnlyStore store = new ReadOnlyStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.store.mkdir("sub");
        store.readOnly = true;

        byte[] iv = h.directoryManager.readDirIV("sub");

        assertEquals(Constants.DIR_IV_LEN, iv.length);
        assertThrows(NoSuchFileException.class, () -> store.readSmall(
                PathResolver.join("sub", Constants.DIR_IV_FILENAME), Constants.DIR_IV_LEN),
                "a read-only store must not get a diriv file written");
    }

    @Test
    void readDirIVOnReadOnlyStoreListsEmptyDirectory() throws IOException {
        ReadOnlyStore store = new ReadOnlyStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.store.mkdir("sub");
        store.readOnly = true;

        byte[] iv = h.directoryManager.readDirIV("sub");
        List<DirEntry> entries = h.directoryManager.listCipherDir("sub", iv);

        assertTrue(entries.isEmpty(),
                "an empty directory without a diriv must list as empty on a read-only store");
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
    void listCipherDirSkipsReservedNamesInPlaintextRoot() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();
        h.fileManager.createFile("/normal.txt");
        for (String name : Arrays.asList("gocryptfs.conf.bak", "gocryptfs.diriv",
                "gocryptfs.anything", ".gocryptfs-abc.tmp", ".gocryptfs.lock")) {
            h.store.writeSmall(PathResolver.join(h.store.root(), name),
                    new byte[]{1}, false);
        }

        byte[] iv = h.directoryManager.readDirIV(h.store.root());
        List<DirEntry> entries = h.directoryManager.listCipherDir(h.store.root(), iv);

        Set<String> names = entries.stream()
                .map(DirEntry::plainName)
                .collect(Collectors.toSet());
        assertEquals(new HashSet<>(Arrays.asList("normal.txt")), names);
    }

    @Test
    void listCipherDirSkipsHiddenInternalNamesInSubdirectories() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();
        h.fileManager.mkdir("/dir");
        h.fileManager.createFile("/dir/gocryptfs.conf.bak");
        h.store.writeSmall(PathResolver.join("dir", ".gocryptfs-abc.tmp"),
                new byte[]{1}, false);

        String cipherPath = h.pathResolver.resolve("/dir").cipherPath;
        byte[] iv = h.directoryManager.readDirIV(cipherPath);
        List<DirEntry> entries = h.directoryManager.listCipherDir(cipherPath, iv);

        assertEquals(1, entries.size());
        assertEquals("gocryptfs.conf.bak", entries.get(0).plainName());
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

        try (SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true);
             BlockBufferedChannel ch = cf.newChannel(0, true)) {
            // A single short block stays in the channel's buffer and is not yet
            // written through, but listing must still report its plaintext size.
            ch.write(ByteBuffer.wrap(new byte[100]));

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

    /**
     * A {@link CipherStore} over an in-memory store whose control-file writes
     * can be disabled, simulating a read-only medium.
     */
    private static final class ReadOnlyStore implements CipherStore {

        private final MapCipherStore delegate = new MapCipherStore();
        boolean readOnly;
        boolean listingConsistent = true;

        @Override
        public String root() {
            return delegate.root();
        }

        @Override
        public boolean isListingConsistent() {
            return listingConsistent;
        }

        @Override
        public byte[] readSmall(String name, int maxBytes) throws IOException {
            return delegate.readSmall(name, maxBytes);
        }

        @Override
        public void writeSmall(String name, byte[] data, boolean overwrite) throws IOException {
            if (readOnly) {
                throw new IOException("read-only store");
            }
            delegate.writeSmall(name, data, overwrite);
        }

        @Override
        public CipherNode stat(String name) throws IOException {
            return delegate.stat(name);
        }

        @Override
        public List<CipherNode> list(String dir) throws IOException {
            return delegate.list(dir);
        }

        @Override
        public void createFile(String name) throws IOException {
            delegate.createFile(name);
        }

        @Override
        public void mkdir(String name) throws IOException {
            delegate.mkdir(name);
        }

        @Override
        public void delete(String name) throws IOException {
            delegate.delete(name);
        }

        @Override
        public void rename(String from, String to, boolean replaceExisting) throws IOException {
            delegate.rename(from, to, replaceExisting);
        }

        @Override
        public void createSymlink(String name, String target) throws IOException {
            delegate.createSymlink(name, target);
        }

        @Override
        public String readSymlink(String name) throws IOException {
            return delegate.readSymlink(name);
        }

        @Override
        public void setTimes(String name, @Nullable FileTime lastModifiedTime,
                             @Nullable FileTime lastAccessTime, @Nullable FileTime creationTime)
                throws IOException {
            delegate.setTimes(name, lastModifiedTime, lastAccessTime, creationTime);
        }

        @Override
        public CipherChannel open(String name, boolean writable) throws IOException {
            return delegate.open(name, writable);
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
