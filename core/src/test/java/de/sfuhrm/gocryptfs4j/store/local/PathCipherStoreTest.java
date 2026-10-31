package de.sfuhrm.gocryptfs4j.store.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tests the local-filesystem-specific regular-file check in
 * {@link PathCipherStore#readSmall}.
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
}
