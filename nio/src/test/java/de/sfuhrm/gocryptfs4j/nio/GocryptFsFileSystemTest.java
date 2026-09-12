package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Tests for the basic properties and lifecycle of {@link GocryptFsFileSystem}. */
class GocryptFsFileSystemTest {

    @TempDir
    Path tmp;

    @Test
    void properties() throws IOException {
        Path cipherDir = createCipherDir("props");
        try (FileSystem fs = new GocryptFsProvider().newFileSystem(cipherDir, "pw".toCharArray())) {
            assertTrue(fs.isOpen());
            assertFalse(fs.isReadOnly());
            assertEquals("/", fs.getSeparator());
            assertNotNull(fs.provider());

            List<Path> roots = new ArrayList<>();
            fs.getRootDirectories().forEach(roots::add);
            assertEquals(1, roots.size());
            assertEquals("/", roots.get(0).toString());

            assertTrue(fs.getFileStores().iterator().hasNext());
            assertTrue(fs.supportedFileAttributeViews().contains("basic"));
            assertTrue(fs.toString().startsWith("gocryptfs://"));
        }
    }

    @Test
    void watchServiceLifecycle() throws IOException {
        Path cipherDir = createCipherDir("watch");
        FileSystem fs = new GocryptFsProvider().newFileSystem(cipherDir, "pw".toCharArray());
        try (WatchService watcher = fs.newWatchService()) {
            assertNotNull(watcher);
        }
        fs.close();
        fs.close();
        assertFalse(fs.isOpen());
        assertThrows(ClosedFileSystemException.class, fs::newWatchService);
    }

    @Test
    void urlDecode() {
        assertEquals("a/b", GocryptFsFileSystem.urlDecode("a%2Fb"));
        assertEquals("%zz", GocryptFsFileSystem.urlDecode("%zz"));
    }

    private Path createCipherDir(String name) throws IOException {
        Path cipherDir = tmp.resolve(name);
        Files.createDirectory(cipherDir);
        try (GocryptFs ignored = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // empty filesystem
        }
        return cipherDir;
    }
}
