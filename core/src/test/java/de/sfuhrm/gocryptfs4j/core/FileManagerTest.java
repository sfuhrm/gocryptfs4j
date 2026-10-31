package de.sfuhrm.gocryptfs4j.core;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.NoSuchFileException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
}
