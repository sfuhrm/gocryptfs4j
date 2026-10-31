package de.sfuhrm.gocryptfs4j.core;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.NotDirectoryException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests {@link PathResolver} in isolation: path normalization, validation and
 * the mapping of plaintext paths to ciphertext paths.
 */
class PathResolverTest {

    @Test
    void normalizeSplitsAndDropsEmptyAndDotComponents() {
        assertEquals(Collections.emptyList(), PathResolver.normalize("/"));
        assertEquals(Collections.emptyList(), PathResolver.normalize(""));
        assertEquals(Arrays.asList("a", "b", "c"), PathResolver.normalize("/a/b/c"));
        assertEquals(Arrays.asList("a", "b", "c"), PathResolver.normalize("a//b/./c/"));
    }

    @Test
    void normalizeRejectsDotDot() {
        assertThrows(IllegalArgumentException.class, () -> PathResolver.normalize("/a/../b"));
    }

    @Test
    void joinJoinsOrReturnsChildForEmptyParent() {
        assertEquals("a/b", PathResolver.join("a", "b"));
        assertEquals("b", PathResolver.join("", "b"));
    }

    @Test
    void baseNameReturnsLastSegment() {
        assertEquals("root", PathResolver.baseName("/a/b/root"));
        assertEquals("root", PathResolver.baseName("root"));
        assertEquals("root", PathResolver.baseName("c:\\a\\root"));
    }

    @Test
    void resolveRootReturnsRootResolution() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();

        PathResolver.Resolved r = h.pathResolver.resolve("/");

        assertEquals(h.store.root(), r.cipherPath);
        assertNull(r.cipherParent);
        assertNull(r.cipherName);
        assertEquals("", r.plainName);
    }

    @Test
    void resolveMapsEachComponentToItsCipherName() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.mkdir("/a");
        h.fileManager.createFile("/a/b.txt");

        PathResolver.Resolved dir = h.pathResolver.resolve("/a");
        PathResolver.Resolved r = h.pathResolver.resolve("/a/b.txt");

        assertEquals("b.txt", r.plainName);
        assertEquals(dir.cipherPath, r.cipherParent);
        assertTrue(!dir.cipherPath.equals("a"), "an encrypted name must not equal its plaintext");
    }

    @Test
    void resolveParentReturnsParentAndBasename() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.mkdir("/a");
        h.fileManager.createFile("/a/b.txt");

        PathResolver.Resolved dir = h.pathResolver.resolve("/a");
        PathResolver.Resolved r = h.pathResolver.resolveParent("/a/b.txt");

        assertEquals("b.txt", r.plainName);
        assertEquals(dir.cipherPath, r.cipherParent);
    }

    @Test
    void resolveRejectsControlFileInPlaintextMode() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();

        assertThrows(IllegalArgumentException.class,
                () -> h.pathResolver.resolve("/gocryptfs.conf"));
    }

    @Test
    void resolveAllowsControlFileNameInSubdirectory() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();
        h.fileManager.mkdir("/sub");
        h.fileManager.createFile("/sub/gocryptfs.conf");

        PathResolver.Resolved r = h.pathResolver.resolve("/sub/gocryptfs.conf");

        assertEquals("gocryptfs.conf", r.plainName);
    }

    @Test
    void resolveThroughSymlinkIntermediateThrows() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();
        h.fileManager.createSymlink("/link", "target");

        assertThrows(NotDirectoryException.class, () -> h.pathResolver.resolve("/link/sub"));
    }

    @Test
    void resolveRequiresIntermediateToBeDirectory() throws IOException {
        ManagerHarness h = ManagerHarness.plaintext();
        h.fileManager.createFile("/file");

        assertThrows(NotDirectoryException.class, () -> h.pathResolver.resolve("/file/sub"));
    }
}
