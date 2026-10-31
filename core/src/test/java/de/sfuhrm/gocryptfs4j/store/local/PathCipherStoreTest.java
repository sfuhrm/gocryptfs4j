package de.sfuhrm.gocryptfs4j.store.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
}
