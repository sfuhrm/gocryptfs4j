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
import java.nio.file.NoSuchFileException;
import java.nio.file.NotLinkException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileStoreAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.EnumSet;
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

        Map<String, Object> followed = Files.readAttributes(nio.getPath("/link"),
                "isSymbolicLink,isRegularFile");
        assertEquals(Boolean.FALSE, followed.get("isSymbolicLink"));
        assertEquals(Boolean.TRUE, followed.get("isRegularFile"));

        Map<String, Object> link = Files.readAttributes(nio.getPath("/link"),
                "isSymbolicLink,isRegularFile", LinkOption.NOFOLLOW_LINKS);
        assertEquals(Boolean.TRUE, link.get("isSymbolicLink"));
        assertEquals(Boolean.FALSE, link.get("isRegularFile"));

        assertThrows(IllegalArgumentException.class, () -> Files.readAttributes(file, "bogus"));
    }

    @Test
    void readAttributesFollowsSymbolicLink() throws IOException {
        Path link = nio.getPath("/link");

        BasicFileAttributes followed = Files.readAttributes(link, BasicFileAttributes.class);
        assertTrue(followed.isRegularFile());
        assertFalse(followed.isSymbolicLink());
        assertEquals(3L, followed.size());

        BasicFileAttributes notFollowed = Files.readAttributes(link, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        assertTrue(notFollowed.isSymbolicLink());
        assertFalse(notFollowed.isRegularFile());
    }

    @Test
    void fileChecksFollowSymbolicLink() throws IOException {
        Path link = nio.getPath("/link");
        assertTrue(Files.isRegularFile(link));
        assertFalse(Files.isDirectory(link));
        assertEquals(3L, Files.size(link));
        assertTrue(Files.exists(link));
        assertFalse(Files.isRegularFile(link, LinkOption.NOFOLLOW_LINKS));
        assertTrue(Files.isSymbolicLink(link));
        assertTrue(Files.isSameFile(link, nio.getPath("/file.txt")));
    }

    @Test
    void directorySymlinkIsFollowed() throws IOException {
        Path dir = nio.getPath("/follow-dir");
        Files.createDirectory(dir);
        Files.write(dir.resolve("inside.txt"), "x".getBytes(StandardCharsets.UTF_8));
        Path link = nio.getPath("/follow-dir-link");
        Files.createSymbolicLink(link, dir);

        assertTrue(Files.isDirectory(link));
        assertTrue(Files.isExecutable(link));
        assertEquals("x", new String(
                Files.readAllBytes(link.resolve("inside.txt")), StandardCharsets.UTF_8));
        try (java.util.stream.Stream<Path> children = Files.list(link)) {
            assertEquals(1, children.count());
        }
    }

    @Test
    void newByteChannelFollowsSymbolicLink() throws IOException {
        Path link = nio.getPath("/link");
        try (java.nio.channels.SeekableByteChannel channel = Files.newByteChannel(
                link, StandardOpenOption.READ)) {
            java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(8);
            assertEquals(3, channel.read(buffer));
            assertEquals("abc", new String(buffer.array(), 0, 3, StandardCharsets.UTF_8));
        }
    }

    @Test
    void attributeViewFollowsSymbolicLink() throws IOException {
        Path link = nio.getPath("/link");

        BasicFileAttributeView followed = Files.getFileAttributeView(
                link, BasicFileAttributeView.class);
        assertFalse(followed.readAttributes().isSymbolicLink());
        assertTrue(followed.readAttributes().isRegularFile());

        BasicFileAttributeView notFollowed = Files.getFileAttributeView(
                link, BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        assertTrue(notFollowed.readAttributes().isSymbolicLink());
        assertFalse(notFollowed.readAttributes().isRegularFile());
    }

    @Test
    void setAttributeFollowsSymbolicLink() throws IOException {
        Path link = nio.getPath("/link");
        FileTime time = FileTime.fromMillis(System.currentTimeMillis() - 300_000);
        Files.setAttribute(link, "lastModifiedTime", time);

        assertEquals(time.toMillis(),
                Files.getLastModifiedTime(nio.getPath("/file.txt")).toMillis());
    }

    @Test
    void danglingSymbolicLinkIsFollowed() throws IOException {
        Path link = nio.getPath("/dangling-follow");
        Files.createSymbolicLink(link, nio.getPath("/nowhere"));

        assertFalse(Files.exists(link));
        assertTrue(Files.exists(link, LinkOption.NOFOLLOW_LINKS));
        assertTrue(Files.isSymbolicLink(link));
        assertThrows(NoSuchFileException.class,
                () -> Files.readAttributes(link, BasicFileAttributes.class));
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
    void createAndReadSymbolicLink() throws IOException {
        Path target = nio.getPath("/file.txt");
        Path link = nio.getPath("/created-link");
        Files.createSymbolicLink(link, target);

        assertTrue(Files.isSymbolicLink(link));
        assertEquals(target, Files.readSymbolicLink(link));
        assertEquals(target, link.toRealPath());
    }

    @Test
    void readSymbolicLinkOfCoreCreatedLink() throws IOException {
        Path target = Files.readSymbolicLink(nio.getPath("/link"));
        assertEquals(nio.getPath("/file.txt"), target);
        assertEquals("/file.txt", target.toString());
    }

    @Test
    void createRelativeSymbolicLink() throws IOException {
        Path link = nio.getPath("/relative-link");
        Files.createSymbolicLink(link, nio.getPath("file.txt"));

        Path target = Files.readSymbolicLink(link);
        assertFalse(target.isAbsolute());
        assertEquals("file.txt", target.toString());
        assertEquals(nio.getPath("/file.txt"), link.toRealPath());
    }

    @Test
    void createDanglingSymbolicLink() throws IOException {
        Path target = nio.getPath("/does-not-exist");
        Path link = nio.getPath("/dangling-link");
        Files.createSymbolicLink(link, target);

        assertTrue(Files.isSymbolicLink(link));
        assertEquals(target, Files.readSymbolicLink(link));
    }

    @Test
    void createSymbolicLinkOnExistingPathFails() {
        assertThrows(FileAlreadyExistsException.class,
                () -> Files.createSymbolicLink(nio.getPath("/file.txt"), nio.getPath("/other")));
    }

    @Test
    void readSymbolicLinkOnRegularFileFails() {
        assertThrows(NotLinkException.class,
                () -> Files.readSymbolicLink(nio.getPath("/file.txt")));
    }

    @Test
    void readSymbolicLinkOnMissingPathFails() {
        assertThrows(NoSuchFileException.class,
                () -> Files.readSymbolicLink(nio.getPath("/missing-link")));
    }

    @Test
    void createNewMissingAndAppend() throws IOException {
        Path duplicate = nio.getPath("/duplicate.txt");
        Files.createFile(duplicate);
        assertThrows(FileAlreadyExistsException.class, () -> Files.createFile(duplicate));

        assertThrows(NoSuchFileException.class, () -> Files.newByteChannel(
                nio.getPath("/missing.txt"), EnumSet.of(StandardOpenOption.READ)));

        Path append = nio.getPath("/append.txt");
        Files.write(append, "a".getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(append, "b".getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);
        assertEquals("ab", new String(Files.readAllBytes(append), StandardCharsets.UTF_8));
    }

    @Test
    void copySymbolicLink() throws IOException {
        Path copy = nio.getPath("/link-copy");
        Files.copy(nio.getPath("/link"), copy);
        assertTrue(Files.isSymbolicLink(copy));
        assertEquals("/file.txt", copy.toRealPath().toString());
    }

    @Test
    void moveDirectoryRecursively() throws IOException {
        Path src = nio.getPath("/move-src");
        Files.createDirectory(src);
        Files.write(src.resolve("f.txt"), "f".getBytes(StandardCharsets.UTF_8));

        Path moved = nio.getPath("/move-dst");
        Files.move(src, moved);
        assertFalse(Files.exists(src));
        assertEquals("f", new String(
                Files.readAllBytes(moved.resolve("f.txt")), StandardCharsets.UTF_8));
    }

    @Test
    void moveSamePathIsNoOp() throws IOException {
        Path file = nio.getPath("/file.txt");
        Files.move(file, file);
        assertTrue(Files.exists(file));
    }

    @Test
    void fileKeyAttribute() throws IOException {
        Map<String, Object> attrs = Files.readAttributes(nio.getPath("/file.txt"), "fileKey");
        assertTrue(attrs.containsKey("fileKey"));
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
