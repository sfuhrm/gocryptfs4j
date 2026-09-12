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
import java.nio.file.PathMatcher;
import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Edge cases of the glob-to-regex translation in {@link GocryptFsPathMatcher}
 * that the higher-level provider tests do not reach.
 */
class GocryptFsPathMatcherTest {

    private static Path cipherDir;
    private static FileSystem nio;

    @BeforeAll
    static void setUp() throws IOException {
        cipherDir = Files.createTempDirectory("gocryptfs-glob-");
        try (GocryptFs ignored = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // empty filesystem
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

    private static PathMatcher glob(String pattern) {
        return GocryptFsPathMatcher.create("glob:" + pattern);
    }

    private static Path p(String path) {
        return nio.getPath(path);
    }

    @Test
    void rejectsInvalidSyntaxAndPattern() {
        assertThrows(IllegalArgumentException.class, () -> GocryptFsPathMatcher.create("glob"));
        assertThrows(IllegalArgumentException.class, () -> GocryptFsPathMatcher.create(":x"));
        assertThrows(IllegalArgumentException.class, () -> GocryptFsPathMatcher.create("glob:"));
        assertThrows(IllegalArgumentException.class, () -> GocryptFsPathMatcher.create("unknown:x"));
        assertThrows(PatternSyntaxException.class, () -> GocryptFsPathMatcher.create("regex:["));
    }

    @Test
    void escapes() {
        assertTrue(glob("a\\.txt").matches(p("a.txt")));
        assertFalse(glob("a\\.txt").matches(p("abtxt")));
        assertTrue(glob("a\\btxt").matches(p("abtxt")));
        assertThrows(PatternSyntaxException.class, () -> GocryptFsPathMatcher.create("glob:abc\\"));
    }

    @Test
    void doubleStar() {
        assertTrue(glob("**/x").matches(p("/x")));
        assertTrue(glob("**/x").matches(p("/a/b/x")));
        assertFalse(glob("**/x").matches(p("/a/b/y")));
        assertTrue(glob("a/**").matches(p("a/b/c")));
        assertTrue(glob("**.txt").matches(p("a/b/c.txt")));
    }

    @Test
    void characterClasses() {
        assertTrue(glob("[abc].txt").matches(p("a.txt")));
        assertFalse(glob("[abc].txt").matches(p("d.txt")));
        assertTrue(glob("[!abc].txt").matches(p("d.txt")));
        assertFalse(glob("[!abc].txt").matches(p("a.txt")));
        assertTrue(glob("[]]x").matches(p("]x")));
        assertTrue(glob("[abc").matches(p("[abc")));
    }

    @Test
    void groupsAndLiterals() {
        assertTrue(glob("{a,b}.txt").matches(p("a.txt")));
        assertTrue(glob("{a,b}.txt").matches(p("b.txt")));
        assertFalse(glob("{a,b}.txt").matches(p("c.txt")));
        assertTrue(glob("a}b").matches(p("a}b")));
        assertTrue(glob("a,b").matches(p("a,b")));
        assertThrows(PatternSyntaxException.class,
                () -> GocryptFsPathMatcher.create("glob:{a,{b,c}}"));
        assertThrows(PatternSyntaxException.class, () -> GocryptFsPathMatcher.create("glob:{a,b"));
    }

    @Test
    void questionMarkAndSingleStar() {
        assertTrue(glob("file?.txt").matches(p("file1.txt")));
        assertFalse(glob("file?.txt").matches(p("file12.txt")));
        assertTrue(glob("a*b").matches(p("axxb")));
        assertFalse(glob("a*b").matches(p("a/xb")));
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
