package de.sfuhrm.gocryptfs4j.nio;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class GocryptFsFeaturesTest {

    @TempDir
    Path tmp;

    private FileSystem open() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        try (de.sfuhrm.gocryptfs4j.core.GocryptFs fs =
                     de.sfuhrm.gocryptfs4j.core.GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // just create the filesystem layout
        }
        return new GocryptFsProvider().newFileSystem(cipherDir, "pw".toCharArray());
    }

    @Test
    void pathMatcherGlob() throws IOException {
        try (FileSystem nio = open()) {
            PathMatcher m = nio.getPathMatcher("glob:**/*.txt");
            assertTrue(m.matches(nio.getPath("/a/b.txt")));
            assertTrue(m.matches(nio.getPath("/x.txt")));
            assertFalse(m.matches(nio.getPath("/x.md")));

            PathMatcher single = nio.getPathMatcher("glob:*.txt");
            assertTrue(single.matches(nio.getPath("a.txt")));
            assertFalse(single.matches(nio.getPath("dir/a.txt")));

            PathMatcher q = nio.getPathMatcher("glob:file?.txt");
            assertTrue(q.matches(nio.getPath("file1.txt")));
            assertFalse(q.matches(nio.getPath("file12.txt")));

            PathMatcher group = nio.getPathMatcher("glob:*.{txt,md}");
            assertTrue(group.matches(nio.getPath("a.txt")));
            assertTrue(group.matches(nio.getPath("a.md")));
            assertFalse(group.matches(nio.getPath("a.java")));
        }
    }

    @Test
    void pathMatcherRegex() throws IOException {
        try (FileSystem nio = open()) {
            PathMatcher m = nio.getPathMatcher("regex:.*\\.txt$");
            assertTrue(m.matches(nio.getPath("/a/b.txt")));
            assertFalse(m.matches(nio.getPath("/a/b.md")));
        }
    }

    @Test
    void pathMatcherRejectsUnknownSyntax() throws IOException {
        try (FileSystem nio = open()) {
            assertThrows(IllegalArgumentException.class,
                    () -> nio.getPathMatcher("unknown:pattern"));
        }
    }

    @Test
    void userPrincipalLookup() throws IOException {
        try (FileSystem nio = open()) {
            UserPrincipalLookupService s = nio.getUserPrincipalLookupService();
            UserPrincipal alice = s.lookupPrincipalByName("alice");
            assertEquals("alice", alice.getName());
            assertEquals(alice, s.lookupPrincipalByName("alice"));
            assertEquals(alice, alice);
            assertFalse(alice.equals("alice"));
            assertNotEquals(alice, s.lookupPrincipalByName("bob"));
            assertEquals("alice", alice.toString());
            assertEquals("alice".hashCode(), alice.hashCode());

            GroupPrincipal staff = s.lookupPrincipalByGroupName("staff");
            assertEquals("staff", staff.getName());
        }
    }

    @Test
    void directoryStreamRejectsIteratorAfterClose() throws IOException {
        GocryptFsDirectoryStream stream =
                new GocryptFsDirectoryStream(Collections.<Path>emptyList());
        stream.close();
        assertThrows(IllegalStateException.class, stream::iterator);
    }

    @Test
    void watchServiceDetectsCreateModifyDelete() throws Exception {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        try (de.sfuhrm.gocryptfs4j.core.GocryptFs fs =
                     de.sfuhrm.gocryptfs4j.core.GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // just create the filesystem layout
        }
        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, "pw".toCharArray())) {
            GocryptFsWatchService ws = new GocryptFsWatchService((GocryptFsFileSystem) nio, 50L);
            Path root = nio.getPath("/");
            WatchKey key = root.register(ws,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_DELETE,
                    StandardWatchEventKinds.ENTRY_MODIFY);

            Path file = root.resolve("hello.txt");
            Files.write(file, "hi".getBytes(StandardCharsets.UTF_8));

            WatchKey created = ws.take();
            assertSame(key, created);
            assertTrue(created.pollEvents().stream().anyMatch(
                    e -> e.kind() == StandardWatchEventKinds.ENTRY_CREATE
                            && "hello.txt".equals(((Path) e.context()).getFileName().toString())));
            assertTrue(created.reset());

            Files.write(file, "hello world".getBytes(StandardCharsets.UTF_8));
            WatchKey modified = ws.take();
            assertTrue(modified.pollEvents().stream().anyMatch(
                    e -> e.kind() == StandardWatchEventKinds.ENTRY_MODIFY));
            assertTrue(modified.reset());

            Files.delete(file);
            WatchKey deleted = ws.take();
            assertTrue(deleted.pollEvents().stream().anyMatch(
                    e -> e.kind() == StandardWatchEventKinds.ENTRY_DELETE));
            assertTrue(deleted.reset());

            ws.close();
            assertFalse(key.isValid());
        }
    }

    @Test
    void registerRequiresAbsolutePath() throws Exception {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        try (de.sfuhrm.gocryptfs4j.core.GocryptFs fs =
                     de.sfuhrm.gocryptfs4j.core.GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // just create the filesystem layout
        }
        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, "pw".toCharArray())) {
            GocryptFsWatchService ws = new GocryptFsWatchService((GocryptFsFileSystem) nio, 50L);
            assertThrows(IllegalArgumentException.class,
                    () -> nio.getPath("relative").register(ws, StandardWatchEventKinds.ENTRY_CREATE));
            ws.close();
        }
    }

    @Test
    void watchServiceCloseInvalidatesAndThrows() throws Exception {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        try (de.sfuhrm.gocryptfs4j.core.GocryptFs fs =
                     de.sfuhrm.gocryptfs4j.core.GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // just create the filesystem layout
        }
        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, "pw".toCharArray())) {
            GocryptFsWatchService ws = new GocryptFsWatchService((GocryptFsFileSystem) nio, 50L);
            ws.close();
            assertThrows(java.nio.file.ClosedWatchServiceException.class, ws::poll);
        }
    }
}
