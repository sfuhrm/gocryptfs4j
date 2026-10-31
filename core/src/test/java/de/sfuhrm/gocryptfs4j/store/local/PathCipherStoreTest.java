package de.sfuhrm.gocryptfs4j.store.local;

import de.sfuhrm.gocryptfs4j.store.CipherNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests the local-filesystem-specific regular-file check in
 * {@link PathCipherStore#readSmall} and the secure-directory-stream traversal.
 */
class PathCipherStoreTest {

    @TempDir
    Path tmp;

    @Test
    void readSmallReadsRegularFile() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        Path file = dir.resolve("f");
        Files.write(file, "hello".getBytes(StandardCharsets.UTF_8));
        PathCipherStore store = new PathCipherStore(dir);
        assertArrayEquals("hello".getBytes(StandardCharsets.UTF_8),
                store.readSmall(file.toString(), 100));
    }

    @Test
    void readSmallRejectsDirectory() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        PathCipherStore store = new PathCipherStore(dir);
        assertThrows(IOException.class, () -> store.readSmall(dir.toString(), 100));
    }

    @Test
    void readSmallRejectsFifoWithoutBlocking() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        Path fifo = dir.resolve("fifo");
        int exit = new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor();
        assumeTrue(exit == 0, "mkfifo is not available");
        PathCipherStore store = new PathCipherStore(dir);
        assertThrows(IOException.class, () -> store.readSmall(fifo.toString(), 100));
    }

    @Test
    void readSmallRejectsSymlink() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        Path target = dir.resolve("real");
        Files.write(target, "hello".getBytes(StandardCharsets.UTF_8));
        Path link = dir.resolve("link");
        Files.createSymbolicLink(link, target);
        PathCipherStore store = new PathCipherStore(dir);
        assertThrows(IOException.class, () -> store.readSmall(link.toString(), 100));
    }

    @Test
    void renameReplaceExistingReplacesFile() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        PathCipherStore store = new PathCipherStore(dir);
        Path src = dir.resolve("src");
        Files.write(src, "source".getBytes(StandardCharsets.UTF_8));
        Path dst = dir.resolve("dst");
        Files.write(dst, "target".getBytes(StandardCharsets.UTF_8));

        store.rename(src.toString(), dst.toString(), true);

        assertArrayEquals("source".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(dst));
        assertTrue(Files.notExists(src), "source must be moved away");
    }

    @Test
    void renameReplaceExistingPreservesTargetOnFailure() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        PathCipherStore store = new PathCipherStore(dir);
        Path src = dir.resolve("src");
        Files.write(src, "source".getBytes(StandardCharsets.UTF_8));
        Path dst = dir.resolve("dst");
        Files.createDirectory(dst);
        Path child = dst.resolve("child");
        Files.write(child, "child".getBytes(StandardCharsets.UTF_8));

        assertThrows(IOException.class, () -> store.rename(src.toString(), dst.toString(), true));

        assertTrue(Files.isDirectory(dst), "target must survive a failed replace");
        assertArrayEquals("child".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(child));
        assertTrue(Files.exists(src), "source must survive a failed replace");
    }

    @Test
    void renameReplaceExistingAcrossFileStoresFallsBackGracefully() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        PathCipherStore store = new PathCipherStore(dir);

        Path otherFs = Paths.get("/dev/shm");
        assumeTrue(Files.isDirectory(otherFs) && Files.isWritable(otherFs),
                "/dev/shm is not a writable directory");
        assumeTrue(!Files.getFileStore(dir).equals(Files.getFileStore(otherFs)),
                "/dev/shm is not a distinct file store");

        Path src = dir.resolve("src");
        Files.write(src, "source".getBytes(StandardCharsets.UTF_8));
        Path dst = Files.createTempFile(otherFs, "gocryptfs4j-", ".dst");
        Files.write(dst, "target".getBytes(StandardCharsets.UTF_8));

        store.rename(src.toString(), dst.toString(), true);

        assertArrayEquals("source".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(dst));
        assertTrue(Files.notExists(src), "source must be moved away");
    }

    @Test
    void writeSmallCreatesNewFile() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        PathCipherStore store = new PathCipherStore(dir);
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);

        store.writeSmall(dir.resolve("gocryptfs.conf").toString(), data, false);

        assertArrayEquals(data, Files.readAllBytes(dir.resolve("gocryptfs.conf")));
        assertNoTempFiles(dir);
    }

    @Test
    void writeSmallRefusesToOverwriteWhenAsked() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        PathCipherStore store = new PathCipherStore(dir);
        Path conf = dir.resolve("gocryptfs.conf");
        Files.write(conf, "old".getBytes(StandardCharsets.UTF_8));

        assertThrows(FileAlreadyExistsException.class,
                () -> store.writeSmall(conf.toString(), "new".getBytes(StandardCharsets.UTF_8), false));

        assertArrayEquals("old".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(conf));
        assertNoTempFiles(dir);
    }

    @Test
    void writeSmallReplacesContent() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        PathCipherStore store = new PathCipherStore(dir);
        Path conf = dir.resolve("gocryptfs.conf");
        store.writeSmall(conf.toString(), "old".getBytes(StandardCharsets.UTF_8), false);

        store.writeSmall(conf.toString(), "new".getBytes(StandardCharsets.UTF_8), true);

        assertArrayEquals("new".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(conf));
        assertNoTempFiles(dir);
    }

    @Test
    void writeConfigCreatesNewFileWithOwnerOnlyPermissions() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        assumeTrue(Files.getFileAttributeView(dir, PosixFileAttributeView.class) != null,
                "POSIX attributes are not supported");
        PathCipherStore store = new PathCipherStore(dir);
        Path conf = dir.resolve("gocryptfs.conf");
        byte[] data = "x".getBytes(StandardCharsets.UTF_8);

        store.writeConfig(conf.toString(), data, false);

        assertArrayEquals(data, Files.readAllBytes(conf));
        assertEquals(PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(conf));
        assertNoTempFiles(dir);
    }

    @Test
    void writeConfigRefusesToOverwriteWhenAsked() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        PathCipherStore store = new PathCipherStore(dir);
        Path conf = dir.resolve("gocryptfs.conf");
        Files.write(conf, "old".getBytes(StandardCharsets.UTF_8));

        assertThrows(FileAlreadyExistsException.class,
                () -> store.writeConfig(conf.toString(), "new".getBytes(StandardCharsets.UTF_8), false));

        assertArrayEquals("old".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(conf));
        assertNoTempFiles(dir);
    }

    @Test
    void writeConfigReplacesContentAndKeepsPermissions() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("cipher"));
        assumeTrue(Files.getFileAttributeView(dir, PosixFileAttributeView.class) != null,
                "POSIX attributes are not supported");
        PathCipherStore store = new PathCipherStore(dir);
        Path conf = dir.resolve("gocryptfs.conf");
        store.writeConfig(conf.toString(), "old".getBytes(StandardCharsets.UTF_8), false);

        store.writeConfig(conf.toString(), "new".getBytes(StandardCharsets.UTF_8), true);

        assertArrayEquals("new".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(conf));
        assertEquals(PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(conf));
        assertNoTempFiles(dir);
    }

    @Test
    void statOnFilesystemRootDoesNotThrow() throws Exception {
        Path root = Paths.get("/");
        assumeTrue(Files.isDirectory(root), "filesystem root '/' is not a directory");
        PathCipherStore store = new PathCipherStore(root);
        assertTrue(store.stat(root.toString()).isDirectory());
    }

    private static void assertNoTempFiles(Path dir) throws IOException {
        try (java.util.stream.Stream<Path> entries = Files.list(dir)) {
            assertTrue(entries.noneMatch(p -> p.getFileName().toString().startsWith(".gocryptfs-")),
                    "leftover temporary file in " + dir);
        }
    }

    @SuppressWarnings("unchecked")
    private static SecureDirectoryStream<Path> mockSecureDirectory() {
        return (SecureDirectoryStream<Path>) mock(SecureDirectoryStream.class);
    }

    @Test
    void secureStatTraversesIntermediateDirectoriesWithoutFollowingSymlinks() throws Exception {
        SecureDirectoryStream<Path> root = mockSecureDirectory();
        SecureDirectoryStream<Path> sub = mockSecureDirectory();
        when(root.newDirectoryStream(Paths.get("d"), LinkOption.NOFOLLOW_LINKS)).thenReturn(sub);
        BasicFileAttributeView view = mock(BasicFileAttributeView.class);
        BasicFileAttributes attrs = mock(BasicFileAttributes.class);
        when(attrs.isRegularFile()).thenReturn(true);
        when(view.readAttributes()).thenReturn(attrs);
        when(sub.getFileAttributeView(Paths.get("f"), BasicFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS)).thenReturn(view);

        PathCipherStore store = new PathCipherStore(tmp.resolve("cipher"), root);
        CipherNode node = store.stat(tmp.resolve("cipher").resolve("d").resolve("f").toString());

        assertTrue(node.isRegularFile());
        verify(root).newDirectoryStream(Paths.get("d"), LinkOption.NOFOLLOW_LINKS);
        verify(sub).getFileAttributeView(Paths.get("f"), BasicFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        verify(sub).close();
    }

    @Test
    void secureTraversalRejectsSymlinkIntermediateDirectory() throws Exception {
        SecureDirectoryStream<Path> root = mockSecureDirectory();
        when(root.newDirectoryStream(Paths.get("d"), LinkOption.NOFOLLOW_LINKS))
                .thenThrow(new IOException("symlink"));
        PathCipherStore store = new PathCipherStore(tmp.resolve("cipher"), root);

        assertThrows(IOException.class,
                () -> store.stat(tmp.resolve("cipher").resolve("d").resolve("f").toString()));
        verify(root).newDirectoryStream(Paths.get("d"), LinkOption.NOFOLLOW_LINKS);
    }

    @Test
    void secureReadSmallOpensFinalComponentWithNoFollow() throws Exception {
        SecureDirectoryStream<Path> root = mockSecureDirectory();
        SecureDirectoryStream<Path> sub = mockSecureDirectory();
        when(root.newDirectoryStream(Paths.get("d"), LinkOption.NOFOLLOW_LINKS)).thenReturn(sub);
        BasicFileAttributeView view = mock(BasicFileAttributeView.class);
        BasicFileAttributes attrs = mock(BasicFileAttributes.class);
        when(attrs.isRegularFile()).thenReturn(true);
        when(view.readAttributes()).thenReturn(attrs);
        when(sub.getFileAttributeView(Paths.get("f"), BasicFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS)).thenReturn(view);
        SeekableByteChannel channel = mock(SeekableByteChannel.class);
        when(channel.read(any(ByteBuffer.class))).thenReturn(-1);
        when(sub.newByteChannel(Mockito.eq(Paths.get("f")), any())).thenReturn(channel);

        PathCipherStore store = new PathCipherStore(tmp.resolve("cipher"), root);
        byte[] data = store.readSmall(
                tmp.resolve("cipher").resolve("d").resolve("f").toString(), 100);

        assertEquals(0, data.length);
        ArgumentCaptor<Set> options = ArgumentCaptor.forClass(Set.class);
        verify(sub).newByteChannel(Mockito.eq(Paths.get("f")), options.capture());
        assertTrue(options.getValue().contains(LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    void secureListOnRootDoesNotOpenSubdirectory() throws Exception {
        SecureDirectoryStream<Path> root = mockSecureDirectory();
        when(root.iterator()).thenReturn(Collections.<Path>emptyIterator());
        when(root.newDirectoryStream(any(Path.class), any(LinkOption[].class)))
                .thenThrow(new AssertionError("list(root) must not open a sub-directory"));
        PathCipherStore store = new PathCipherStore(tmp.resolve("cipher"), root);

        assertTrue(store.list(store.root()).isEmpty());
        verify(root, never()).newDirectoryStream(any(Path.class), any(LinkOption[].class));
    }
}
