package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileStoreAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers the {@code FileStore}, attribute-view and copy/move operations of the
 * NIO provider. A single provider filesystem is shared to keep the scrypt setup
 * cost low; tests use unique names so they stay independent.
 */
class GocryptFsProviderOperationsTest {

    private static Path cipherDir;
    private static FileSystem nio;

    @BeforeAll
    static void setUp() throws IOException {
        cipherDir = Files.createTempDirectory("gocryptfs-ops-");
        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.mkdir("/dir");
            fs.createFile("/file.txt");
            fs.write("/file.txt", 0, "abc".getBytes(StandardCharsets.UTF_8));
            fs.createSymlink("/link", "/file.txt");
        }
        nio = new GocryptFsProvider().newFileSystem(cipherDir, "pw".toCharArray());
    }

    @AfterAll
    static void tearDown() throws IOException {
        if (nio != null) {
            nio.close();
        }
        deleteRecursively(cipherDir);
    }

    @Test
    void fileStore() throws IOException {
        FileStore store = Files.getFileStore(nio.getPath("/"));
        assertEquals("gocryptfs", store.name());
        assertEquals("gocryptfs", store.type());
        assertFalse(store.isReadOnly());
        assertTrue(store.supportsFileAttributeView(BasicFileAttributeView.class));
        assertTrue(store.supportsFileAttributeView("basic"));
        assertNull(store.getFileStoreAttributeView(FileStoreAttributeView.class));
        assertTrue(store.getTotalSpace() >= 0);
        assertTrue(store.getUsableSpace() >= 0);
        assertTrue(store.getUnallocatedSpace() >= 0);
        assertEquals(store.getTotalSpace(), store.getAttribute("totalSpace"));
        assertEquals(store.getUsableSpace(), store.getAttribute("usableSpace"));
        assertEquals(store.getUnallocatedSpace(), store.getAttribute("unallocatedSpace"));
        assertNull(store.getAttribute("unknown"));
    }

    @Test
    void basicAttributeView() throws IOException {
        Path file = nio.getPath("/file.txt");
        BasicFileAttributeView view = Files.getFileAttributeView(file, BasicFileAttributeView.class);
        assertNotNull(view);
        assertEquals("basic", view.name());

        BasicFileAttributes attrs = view.readAttributes();
        assertTrue(attrs.isRegularFile());
        assertFalse(attrs.isDirectory());
        assertFalse(attrs.isSymbolicLink());
        assertFalse(attrs.isOther());
        assertEquals(3L, attrs.size());
        assertNotNull(attrs.creationTime());
        assertNotNull(attrs.lastAccessTime());
        assertNotNull(attrs.lastModifiedTime());
        attrs.fileKey();

        FileTime time = FileTime.fromMillis(System.currentTimeMillis() - 60_000);
        view.setTimes(time, null, null);
        assertEquals(time.toMillis(), Files.getLastModifiedTime(file).toMillis());
    }

    @Test
    void attributesByName() throws IOException {
        Path file = nio.getPath("/file.txt");
        Map<String, Object> attrs = Files.readAttributes(file,
                "size,isRegularFile,isDirectory,isSymbolicLink,isOther,"
                        + "creationTime,lastModifiedTime,lastAccessTime");
        assertEquals(3L, attrs.get("size"));
        assertEquals(Boolean.TRUE, attrs.get("isRegularFile"));
        assertEquals(Boolean.FALSE, attrs.get("isDirectory"));
        assertEquals(Boolean.FALSE, attrs.get("isSymbolicLink"));
        assertEquals(Boolean.FALSE, attrs.get("isOther"));
        assertNotNull(attrs.get("creationTime"));
        assertNotNull(attrs.get("lastModifiedTime"));
        assertNotNull(attrs.get("lastAccessTime"));

        Map<String, Object> prefixed = Files.readAttributes(file, "basic:size");
        assertEquals(3L, prefixed.get("basic:size"));

        Map<String, Object> link = Files.readAttributes(nio.getPath("/link"),
                "isSymbolicLink,isRegularFile");
        assertEquals(Boolean.TRUE, link.get("isSymbolicLink"));
        assertEquals(Boolean.FALSE, link.get("isRegularFile"));

        assertThrows(IllegalArgumentException.class, () -> Files.readAttributes(file, "bogus"));
    }

    @Test
    void setAttributes() throws IOException {
        Path file = nio.getPath("/setattr.txt");
        Files.write(file, "x".getBytes(StandardCharsets.UTF_8));

        FileTime time = FileTime.fromMillis(System.currentTimeMillis() - 120_000);
        Files.setAttribute(file, "lastModifiedTime", time);
        Files.setAttribute(file, "basic:lastAccessTime", time);
        Files.setAttribute(file, "basic:creationTime", time);
        assertEquals(time.toMillis(), Files.getLastModifiedTime(file).toMillis());

        assertThrows(UnsupportedOperationException.class,
                () -> Files.setAttribute(file, "bogus", time));
    }

    @Test
    void unsupportedAttributeViews() throws IOException {
        Path file = nio.getPath("/file.txt");
        assertNull(Files.getFileAttributeView(file, PosixFileAttributeView.class));
        assertThrows(UnsupportedOperationException.class,
                () -> Files.readAttributes(file, PosixFileAttributes.class));
    }

    @Test
    void accessAndIdentity() throws IOException {
        Path file = nio.getPath("/file.txt");
        Path dir = nio.getPath("/dir");
        assertTrue(Files.isReadable(file));
        assertTrue(Files.isWritable(file));
        assertFalse(Files.isExecutable(file));
        assertTrue(Files.isExecutable(dir));
        assertFalse(Files.isHidden(file));

        Path hidden = nio.getPath("/.hidden");
        Files.write(hidden, new byte[0]);
        assertTrue(Files.isHidden(hidden));

        assertDoesNotThrow(() -> Files.isSameFile(file, file));
        assertFalse(Files.isSameFile(file, dir));
    }

    @Test
    void copyAndMove() throws IOException {
        Path source = nio.getPath("/copy-src.txt");
        Files.write(source, "data".getBytes(StandardCharsets.UTF_8));

        Path target = nio.getPath("/copy-dst.txt");
        Files.copy(source, target);
        assertArrayEquals("data".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(target));

        assertThrows(FileAlreadyExistsException.class, () -> Files.copy(source, target));
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        assertArrayEquals("data".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(target));

        Path moved = nio.getPath("/copy-moved.txt");
        Files.move(target, moved);
        assertFalse(Files.exists(target));
        assertTrue(Files.exists(moved));

        assertThrows(AtomicMoveNotSupportedException.class,
                () -> Files.move(moved, nio.getPath("/copy-atomic.txt"),
                        StandardCopyOption.ATOMIC_MOVE));
        assertFalse(Files.exists(nio.getPath("/copy-atomic.txt")));
    }

    @Test
    void copyDirectoryTree() throws IOException {
        Path dir = nio.getPath("/tree");
        Files.createDirectory(dir);
        Files.write(dir.resolve("a.txt"), "a".getBytes(StandardCharsets.UTF_8));
        Files.createDirectory(dir.resolve("sub"));

        Path copy = nio.getPath("/tree-copy");
        Files.copy(dir, copy);
        assertTrue(Files.isDirectory(copy));
        assertEquals("a", new String(
                Files.readAllBytes(copy.resolve("a.txt")), StandardCharsets.UTF_8));
        assertTrue(Files.isDirectory(copy.resolve("sub")));
    }

    @Test
    void creatingSymbolicLinkIsUnsupported() {
        assertThrows(UnsupportedOperationException.class,
                () -> Files.createSymbolicLink(nio.getPath("/new-link"), nio.getPath("/file.txt")));
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (path == null || !Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            try (java.util.stream.Stream<Path> children = Files.list(path)) {
                for (Path child : children.collect(java.util.stream.Collectors.toList())) {
                    deleteRecursively(child);
                }
            }
        }
        Files.deleteIfExists(path);
    }
}
