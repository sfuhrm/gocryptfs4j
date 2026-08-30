package de.sfuhrm.gocryptfs4j.fs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DirEntryTest {

    private static final FileTime MTIME = FileTime.fromMillis(1_000_000L);
    private static final FileTime ATIME = FileTime.fromMillis(2_000_000L);
    private static final FileTime CTIME = FileTime.fromMillis(3_000_000L);

    private static DirEntry entry(DirEntry.Kind kind) {
        return new DirEntry("plain", "cipher", Path.of("/x/cipher"), kind, 42L,
                MTIME, ATIME, CTIME, "key");
    }

    @Test
    void gettersReturnConstructorValues() {
        DirEntry e = entry(DirEntry.Kind.FILE);

        assertEquals("plain", e.plainName());
        assertEquals("cipher", e.cipherName());
        assertEquals(Path.of("/x/cipher"), e.cipherPath());
        assertEquals(DirEntry.Kind.FILE, e.kind());
        assertEquals(42L, e.size());
        assertEquals(MTIME, e.lastModifiedTime());
        assertEquals(ATIME, e.lastAccessTime());
        assertEquals(CTIME, e.creationTime());
        assertEquals("key", e.fileKey());
    }

    @Test
    void kindPredicates() {
        assertTrue(entry(DirEntry.Kind.DIRECTORY).isDirectory());
        assertFalse(entry(DirEntry.Kind.DIRECTORY).isRegularFile());
        assertFalse(entry(DirEntry.Kind.DIRECTORY).isSymbolicLink());

        assertTrue(entry(DirEntry.Kind.FILE).isRegularFile());
        assertFalse(entry(DirEntry.Kind.FILE).isDirectory());
        assertFalse(entry(DirEntry.Kind.FILE).isSymbolicLink());

        assertTrue(entry(DirEntry.Kind.SYMLINK).isSymbolicLink());
        assertFalse(entry(DirEntry.Kind.SYMLINK).isDirectory());
        assertFalse(entry(DirEntry.Kind.SYMLINK).isRegularFile());

        assertFalse(entry(DirEntry.Kind.OTHER).isDirectory());
        assertFalse(entry(DirEntry.Kind.OTHER).isRegularFile());
        assertFalse(entry(DirEntry.Kind.OTHER).isSymbolicLink());
    }

    @TempDir
    Path tmp;

    @Test
    void listedEntriesReflectFilesystem() throws Exception {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] content = "hello filesystem".getBytes(StandardCharsets.UTF_8);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.mkdir("/docs");
            fs.createFile("/docs/note.txt");
            fs.write("/docs/note.txt", 0, content);
        }

        try (GocryptFs fs = GocryptFs.open(cipherDir, "pw".toCharArray())) {
            List<DirEntry> root = fs.list("/");
            assertEquals(1, root.size());
            assertEquals("docs", root.get(0).plainName());
            assertEquals(DirEntry.Kind.DIRECTORY, root.get(0).kind());
            assertTrue(root.get(0).isDirectory());
            assertEquals(0L, root.get(0).size());
            assertNotNull(root.get(0).fileKey());
            assertNotNull(root.get(0).cipherPath());

            List<DirEntry> docs = fs.list("/docs");
            assertEquals(1, docs.size());
            DirEntry note = docs.get(0);
            assertEquals("note.txt", note.plainName());
            assertEquals(DirEntry.Kind.FILE, note.kind());
            assertTrue(note.isRegularFile());
            assertEquals(content.length, note.size());

            DirEntry stat = fs.stat("/docs/note.txt");
            assertEquals("note.txt", stat.plainName());
            assertEquals(DirEntry.Kind.FILE, stat.kind());
            assertEquals(content.length, stat.size());
        }
    }

    @Test
    void symlinkEntryKindAndSize() throws Exception {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/target.txt");
            fs.write("/target.txt", 0, "data".getBytes(StandardCharsets.UTF_8));
            fs.createSymlink("/link.txt", "target.txt");
        }

        try (GocryptFs fs = GocryptFs.open(cipherDir, "pw".toCharArray())) {
            List<DirEntry> root = fs.list("/");
            DirEntry link = root.stream()
                    .filter(e -> e.plainName().equals("link.txt"))
                    .findFirst().orElseThrow();
            assertEquals(DirEntry.Kind.SYMLINK, link.kind());
            assertTrue(link.isSymbolicLink());
            assertEquals("target.txt".length(), link.size());
        }
    }
}
