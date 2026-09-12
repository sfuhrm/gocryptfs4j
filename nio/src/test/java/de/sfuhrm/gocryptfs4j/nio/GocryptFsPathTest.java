package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.WatchEvent;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the pure path logic of {@link GocryptFsPath}. A single
 * provider filesystem is shared by all tests to keep the scrypt setup cost low;
 * the tests only read it.
 */
class GocryptFsPathTest {

    private static Path cipherDir;
    private static FileSystem nio;

    @BeforeAll
    static void setUp() throws IOException {
        cipherDir = Files.createTempDirectory("gocryptfs-path-");
        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.mkdir("/target");
            fs.createFile("/file.txt");
            fs.createSymlink("/link", "/target");
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
    void absolutePathDetails() {
        Path p = nio.getPath("/a/b/c");
        assertTrue(p.isAbsolute());
        assertEquals(3, p.getNameCount());
        assertEquals("c", p.getFileName().toString());
        assertEquals("/a/b", p.getParent().toString());
        assertEquals("/", p.getRoot().toString());
        assertEquals("/a/b/c", p.toString());

        List<String> names = new ArrayList<>();
        Iterator<Path> it = p.iterator();
        while (it.hasNext()) {
            names.add(it.next().toString());
        }
        assertEquals(Arrays.asList("a", "b", "c"), names);
    }

    @Test
    void relativePathDetails() {
        Path r = nio.getPath("a/b");
        assertFalse(r.isAbsolute());
        assertNull(r.getRoot());
        assertEquals(2, r.getNameCount());
        assertEquals("b", r.getFileName().toString());
        assertEquals("a", r.getParent().toString());
        assertEquals("a/b", r.toString());
    }

    @Test
    void rootHasNoNameOrParent() {
        Path root = nio.getPath("/");
        assertEquals(0, root.getNameCount());
        assertNull(root.getFileName());
        assertNull(root.getParent());
        assertEquals("/", root.toString());
    }

    @Test
    void normalization() {
        assertEquals("/a/c", nio.getPath("/a/./b/../c").toString());
        assertEquals("/", nio.getPath("/..").toString());
        assertEquals("a/b", nio.getPath("a//b/").toString());
        assertEquals("a/b", nio.getPath("a\\b").toString());
        assertEquals("../x", nio.getPath("../x").toString());
    }

    @Test
    void resolveBehaviors() {
        Path base = nio.getPath("/a");
        assertEquals("/a/b", base.resolve("b").toString());
        assertEquals("/x", base.resolve("/x").toString());
        assertEquals("/x", nio.getPath("/").resolve("x").toString());
        assertSame(base, base.resolve((String) null));

        Path absolute = nio.getPath("/z");
        assertSame(absolute, base.resolve(absolute));
    }

    @Test
    void resolveSiblingBehaviors() {
        assertEquals("/a/c", nio.getPath("/a/b").resolveSibling("c").toString());
        assertEquals("c", nio.getPath("a").resolveSibling("c").toString());
    }

    @Test
    void relativizeBehaviors() {
        assertEquals("../d", nio.getPath("/a/b").relativize(nio.getPath("/a/d")).toString());
        assertEquals("b/c", nio.getPath("/a").relativize(nio.getPath("/a/b/c")).toString());
        assertEquals("", nio.getPath("/a").relativize(nio.getPath("/a")).toString());
        assertThrows(IllegalArgumentException.class,
                () -> nio.getPath("/a").relativize(nio.getPath("b")));
    }

    @Test
    void startsWithAndEndsWith() {
        Path p = nio.getPath("/a/b/c");
        assertTrue(p.startsWith("/a"));
        assertTrue(p.startsWith("/a/b/c"));
        assertTrue(p.startsWith("/"));
        assertFalse(p.startsWith("/x"));
        assertFalse(p.startsWith(Paths.get("/a")));

        assertTrue(p.endsWith("c"));
        assertTrue(p.endsWith("b/c"));
        assertTrue(p.endsWith("/a/b/c"));
        assertFalse(p.endsWith("b"));
        assertFalse(p.endsWith("/"));
        assertFalse(p.endsWith(Paths.get("c")));
    }

    @Test
    void nameAndSubpath() {
        Path p = nio.getPath("/a/b/c");
        assertEquals("a", p.getName(0).toString());
        assertEquals("b/c", p.subpath(1, 3).toString());

        assertThrows(IllegalArgumentException.class, () -> p.getName(3));
        assertThrows(IllegalArgumentException.class, () -> p.getName(-1));
        assertThrows(IllegalArgumentException.class, () -> p.subpath(2, 1));
        assertThrows(IllegalArgumentException.class, () -> p.subpath(-1, 1));
        assertThrows(IllegalArgumentException.class, () -> p.subpath(0, 4));
    }

    @Test
    void toAbsoluteUriAndFile() {
        Path relative = nio.getPath("a/b");
        Path absolute = relative.toAbsolutePath();
        assertTrue(absolute.isAbsolute());
        assertEquals("/a/b", absolute.toString());
        assertSame(absolute, absolute.toAbsolutePath());

        assertTrue(relative.toUri().toString().startsWith("gocryptfs://"));
        assertThrows(UnsupportedOperationException.class, relative::toFile);
    }

    @Test
    void normalizeAndEquality() {
        Path p = nio.getPath("/a/b");
        assertEquals(p, p.normalize());
        assertEquals(p.hashCode(), p.normalize().hashCode());
        assertEquals(p, nio.getPath("/a/b"));
        assertEquals(p.hashCode(), nio.getPath("/a/b").hashCode());
        assertNotEquals(p, nio.getPath("/a/c"));
        assertFalse(p.equals("/a/b"));
    }

    @Test
    void toRealPath() throws IOException {
        Path link = nio.getPath("/link");
        assertEquals("/target", link.toRealPath().toString());
        assertEquals("/link", link.toRealPath(LinkOption.NOFOLLOW_LINKS).toString());

        Path missing = nio.getPath("/missing");
        assertEquals("/missing", missing.toRealPath().toString());
        assertEquals("/file.txt", nio.getPath("file.txt")
                .toRealPath(LinkOption.NOFOLLOW_LINKS).toString());
    }

    @Test
    void registerValidatesArguments() throws IOException {
        Path p = nio.getPath("/a");
        GocryptFsWatchService watcher = new GocryptFsWatchService((GocryptFsFileSystem) nio, 50L);
        try {
            assertThrows(NullPointerException.class, () -> p.register(
                    (WatchService) null, new WatchEvent.Kind<?>[0], new WatchEvent.Modifier[0]));
            assertThrows(NullPointerException.class, () -> p.register(
                    watcher, (WatchEvent.Kind<?>[]) null, new WatchEvent.Modifier[0]));
        } finally {
            watcher.close();
        }
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
