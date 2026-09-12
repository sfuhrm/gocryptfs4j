package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for the {@link GocryptFsFileChannel} seekable channel. */
class GocryptFsFileChannelTest {

    private static Path cipherDir;
    private static FileSystem nio;

    @BeforeAll
    static void setUp() throws IOException {
        cipherDir = Files.createTempDirectory("gocryptfs-channel-");
        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/data.txt");
            fs.write("/data.txt", 0, "0123456789".getBytes(StandardCharsets.UTF_8));
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
    void readOnlyChannel() throws IOException {
        try (SeekableByteChannel ch = Files.newByteChannel(nio.getPath("/data.txt"),
                EnumSet.of(StandardOpenOption.READ))) {
            assertTrue(ch.isOpen());
            assertEquals(0, ch.position());
            assertEquals(10, ch.size());

            ch.position(4);
            assertEquals(4, ch.position());
            ByteBuffer buffer = ByteBuffer.allocate(3);
            assertEquals(3, ch.read(buffer));
            assertArrayEquals("456".getBytes(StandardCharsets.UTF_8), buffer.array());

            assertThrows(IllegalArgumentException.class, () -> ch.position(-1));
            assertThrows(NonWritableChannelException.class,
                    () -> ch.write(ByteBuffer.wrap(new byte[]{1})));
            assertThrows(NonWritableChannelException.class, () -> ch.truncate(1));

            ch.close();
            assertFalse(ch.isOpen());
            ch.close();
        }
    }

    @Test
    void writableChannelWritesAndTruncates() throws IOException {
        Path file = nio.getPath("/channel-w.txt");
        Files.write(file, "0123456789".getBytes(StandardCharsets.UTF_8));

        try (SeekableByteChannel ch = Files.newByteChannel(file,
                EnumSet.of(StandardOpenOption.READ, StandardOpenOption.WRITE))) {
            ch.position(10);
            assertEquals(2, ch.write(ByteBuffer.wrap("XY".getBytes(StandardCharsets.UTF_8))));
            assertEquals(12, ch.size());

            ch.position(12);
            ch.truncate(3);
            assertEquals(3, ch.position());
            assertEquals(3, ch.size());
        }
        assertArrayEquals("012".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(file));
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
