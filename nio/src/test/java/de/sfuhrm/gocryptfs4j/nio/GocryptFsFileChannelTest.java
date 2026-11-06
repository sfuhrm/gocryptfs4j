package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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
        try (GocryptFs fs = GocryptFs.create(new PathCipherStore(cipherDir), "pw".toCharArray())) {
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

    @Test
    void truncateToLargerSizeIsNoOp() throws IOException {
        Path file = nio.getPath("/no-grow.txt");
        Files.write(file, "0123456789".getBytes(StandardCharsets.UTF_8));

        try (SeekableByteChannel ch = Files.newByteChannel(file,
                EnumSet.of(StandardOpenOption.READ, StandardOpenOption.WRITE))) {
            ch.truncate(100);
            assertEquals(10, ch.size());
            assertEquals(0, ch.position());
        }
        assertArrayEquals("0123456789".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(file));
    }

    @Test
    void truncateNegativeSizeThrows() throws IOException {
        Path file = nio.getPath("/negative-trunc.txt");
        Files.write(file, "0123456789".getBytes(StandardCharsets.UTF_8));

        try (SeekableByteChannel ch = Files.newByteChannel(file,
                EnumSet.of(StandardOpenOption.READ, StandardOpenOption.WRITE))) {
            assertThrows(IllegalArgumentException.class, () -> ch.truncate(-1));
        }
    }

    @Test
    void writeOnlyChannelRejectsRead() throws IOException {
        try (SeekableByteChannel ch = Files.newByteChannel(nio.getPath("/data.txt"),
                EnumSet.of(StandardOpenOption.WRITE))) {
            assertThrows(NonReadableChannelException.class,
                    () -> ch.read(ByteBuffer.allocate(1)));
        }
    }

    @Test
    void defaultChannelIsReadOnly() throws IOException {
        try (SeekableByteChannel ch = Files.newByteChannel(nio.getPath("/data.txt"))) {
            ByteBuffer buffer = ByteBuffer.allocate(1);
            assertEquals(1, ch.read(buffer));
            assertThrows(NonWritableChannelException.class,
                    () -> ch.write(ByteBuffer.wrap(new byte[]{1})));
        }
    }

    @Test
    void deleteOnCloseRemovesFile() throws IOException {
        Path file = nio.getPath("/delete-on-close.txt");
        try (SeekableByteChannel ch = Files.newByteChannel(file,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.DELETE_ON_CLOSE)) {
            ch.write(ByteBuffer.wrap("x".getBytes(StandardCharsets.UTF_8)));
        }
        assertFalse(Files.exists(file, LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    void syncAndDsyncWrites() throws IOException {
        Path file = nio.getPath("/synced.txt");
        try (SeekableByteChannel ch = Files.newByteChannel(file,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.SYNC)) {
            ch.write(ByteBuffer.wrap("a".getBytes(StandardCharsets.UTF_8)));
        }
        try (SeekableByteChannel ch = Files.newByteChannel(file,
                StandardOpenOption.WRITE, StandardOpenOption.DSYNC)) {
            ch.position(1);
            ch.write(ByteBuffer.wrap("b".getBytes(StandardCharsets.UTF_8)));
        }
        assertArrayEquals("ab".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(file));
    }

    @Test
    void sparseOptionIsAccepted() throws IOException {
        Path file = nio.getPath("/sparse.txt");
        try (SeekableByteChannel ch = Files.newByteChannel(file,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                StandardOpenOption.SPARSE)) {
            ch.write(ByteBuffer.wrap("x".getBytes(StandardCharsets.UTF_8)));
        }
        assertArrayEquals("x".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(file));
    }

    @Test
    void sparseWriteAfterReadOfHoleKeepsPartialBlockReadable() throws IOException {
        Path file = nio.getPath("/sparse-after-read.txt");
        try (SeekableByteChannel ch = Files.newByteChannel(file,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                StandardOpenOption.WRITE)) {
            byte[] head = new byte[100];
            java.util.Arrays.fill(head, (byte) 0x66);
            ch.write(ByteBuffer.wrap(head));

            long offset = 9000;
            ch.position(offset);
            // Reading at a hole position buffers the empty hole block, so the
            // following write targets an already-buffered block.
            assertEquals(-1, ch.read(ByteBuffer.allocate(10)));
            ch.write(ByteBuffer.wrap(new byte[]{0x55}));
        }

        byte[] all = Files.readAllBytes(file);
        assertEquals(9001, all.length);
        for (int i = 0; i < 100; i++) {
            assertEquals(0x66, all[i], "head byte " + i);
        }
        for (int i = 100; i < 9000; i++) {
            assertEquals(0, all[i], "hole byte " + i);
        }
        assertEquals(0x55, all[9000]);
    }

    @Test
    void twoChannelsOnSameBlockStayCoherent() throws IOException {
        Path file = nio.getPath("/coherent.txt");
        int block = 4096;
        byte[] initial = new byte[block];
        java.util.Arrays.fill(initial, (byte) 0x11);
        try (SeekableByteChannel ch = Files.newByteChannel(file,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer buf = ByteBuffer.wrap(initial);
            while (buf.hasRemaining()) {
                ch.write(buf);
            }
        }

        try (SeekableByteChannel a = Files.newByteChannel(file,
                EnumSet.of(StandardOpenOption.READ, StandardOpenOption.WRITE));
             SeekableByteChannel b = Files.newByteChannel(file,
                     EnumSet.of(StandardOpenOption.READ, StandardOpenOption.WRITE))) {
            // A loads block 0 into the shared cache.
            a.position(0);
            ByteBuffer one = ByteBuffer.allocate(1);
            assertEquals(1, a.read(one));
            assertEquals(0x11, one.get(0));

            // B writes into block 0, then A writes into the same block; neither
            // may overwrite the other with a stale copy.
            b.position(100);
            assertEquals(1, b.write(ByteBuffer.wrap(new byte[]{0x22})));
            a.position(200);
            assertEquals(1, a.write(ByteBuffer.wrap(new byte[]{0x33})));
        }

        byte[] all = Files.readAllBytes(file);
        assertEquals(block, all.length);
        assertEquals(0x11, all[0]);
        assertEquals(0x22, all[100]);
        assertEquals(0x33, all[200]);
    }

    @Test
    void appendWritesAtEndRegardlessOfPosition() throws IOException {
        Path file = nio.getPath("/append.txt");
        Files.write(file, "0123".getBytes(StandardCharsets.UTF_8));

        try (SeekableByteChannel ch = Files.newByteChannel(file,
                EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.APPEND))) {
            ch.position(0);
            assertEquals(2, ch.write(ByteBuffer.wrap("45".getBytes(StandardCharsets.UTF_8))));
            assertEquals(6, ch.size());
        }
        assertArrayEquals("012345".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(file));
    }

    @Test
    void multipleAppendersAppendInOrder() throws IOException {
        Path file = nio.getPath("/append-two.txt");
        Files.write(file, "".getBytes(StandardCharsets.UTF_8));

        try (SeekableByteChannel a = Files.newByteChannel(file,
                EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.APPEND));
             SeekableByteChannel b = Files.newByteChannel(file,
                     EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.APPEND))) {
            a.write(ByteBuffer.wrap("AAA".getBytes(StandardCharsets.UTF_8)));
            b.write(ByteBuffer.wrap("BBB".getBytes(StandardCharsets.UTF_8)));
            a.write(ByteBuffer.wrap("CCC".getBytes(StandardCharsets.UTF_8)));
        }
        assertArrayEquals("AAABBBCCC".getBytes(StandardCharsets.UTF_8), Files.readAllBytes(file));
    }

    @Test
    void concurrentAppendersDoNotOverwriteEachOther() throws Exception {
        Path file = nio.getPath("/append-concurrent.txt");
        Files.write(file, new byte[0]);

        int threads = 8;
        int rounds = 16;
        int tokenLength = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CyclicBarrier start = new CyclicBarrier(threads);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int t = 0; t < threads; t++) {
                final int thread = t;
                futures.add(pool.submit(() -> {
                    try (SeekableByteChannel ch = Files.newByteChannel(file,
                            EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.APPEND))) {
                        for (int r = 0; r < rounds; r++) {
                            start.await();
                            String token = String.format("%03d-%03d-", thread, r);
                            ByteBuffer buf = ByteBuffer.wrap(token.getBytes(StandardCharsets.UTF_8));
                            while (buf.hasRemaining()) {
                                ch.write(buf);
                            }
                        }
                    }
                    return null;
                }));
            }
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdown();
        }

        byte[] all = Files.readAllBytes(file);
        assertEquals(threads * rounds * tokenLength, all.length);
        Set<String> expected = new HashSet<>();
        for (int t = 0; t < threads; t++) {
            for (int r = 0; r < rounds; r++) {
                expected.add(String.format("%03d-%03d-", t, r));
            }
        }
        Set<String> actual = new HashSet<>();
        for (int i = 0; i < all.length; i += tokenLength) {
            actual.add(new String(all, i, tokenLength, StandardCharsets.UTF_8));
        }
        assertEquals(expected, actual);
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
