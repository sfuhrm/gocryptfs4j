package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class IoUtilTest {

    @TempDir
    Path tmp;

    @Test
    void readBoundedReadsRegularFile() throws Exception {
        Path file = tmp.resolve("f");
        Files.write(file, "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertArrayEquals("hello".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                IoUtil.readBounded(file, 100));
    }

    @Test
    void readBoundedRejectsDirectory() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("dir"));
        assertThrows(IOException.class, () -> IoUtil.readBounded(dir, 100));
    }

    @Test
    void readBoundedRejectsFifoWithoutBlocking() throws Exception {
        Path fifo = tmp.resolve("fifo");
        int exit = new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor();
        assumeTrue(exit == 0, "mkfifo is not available");
        assertThrows(IOException.class, () -> IoUtil.readBounded(fifo, 100));
    }
}
