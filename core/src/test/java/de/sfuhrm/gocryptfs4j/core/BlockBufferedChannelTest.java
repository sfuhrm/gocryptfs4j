package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class BlockBufferedChannelTest {

    @TempDir
    Path tmp;

    private ContentEnc enc() {
        return new ContentEnc(Keys.randomBytes(Constants.KEY_LEN), Constants.DEFAULT_IV_BITS / 8);
    }

    private Path newFile() throws IOException {
        Path p = tmp.resolve("file.bin");
        Files.createFile(p);
        return p;
    }

    private BlockBufferedChannel openChannel(Path p, ContentEnc enc, boolean writable)
            throws IOException {
        PathCipherStore store = new PathCipherStore(p.getParent());
        CipherChannel channel = store.open(p.toAbsolutePath().toString(), writable);
        CipherFile cf = CipherFile.open(channel, enc, writable);
        SharedCipherFile.Entry entry = new SharedCipherFile.Entry();
        entry.file = cf;
        entry.refs = 1;
        entry.writable = writable;
        try (SharedCipherFile scf = new SharedCipherFile(entry)) {
            return scf.newChannel(0, writable);
        }
    }

    private static byte[] readAll(BlockBufferedChannel ch) throws IOException {
        ch.position(0);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        while (true) {
            int n = ch.read(ByteBuffer.wrap(buf));
            if (n < 0) {
                break;
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    @Test
    void appendDrainsWholeBufferAcrossBlockBoundaries() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) (enc.plainBS() * 2 + 3)];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 29);
        }

        try (BlockBufferedChannel ch = openChannel(newFile(), enc, true)) {
            ByteBuffer buf = ByteBuffer.wrap(data);
            assertEquals(data.length, ch.append(buf));
            assertEquals(0, buf.remaining(), "append must drain the whole buffer");
            assertArrayEquals(data, readAll(ch));
        }
    }

    @Test
    void writeAndReadRoundTripSingleBlock() throws IOException {
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0x5a);

        try (BlockBufferedChannel ch = openChannel(newFile(), enc(), true)) {
            assertEquals(data.length, ch.write(ByteBuffer.wrap(data)));
            assertEquals(data.length, ch.size());
            assertArrayEquals(data, readAll(ch));
        }
    }

    @Test
    void writeAndReadRoundTripMultiBlock() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) (enc.plainBS() * 2 + 100)];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 31);
        }

        try (BlockBufferedChannel ch = openChannel(newFile(), enc, true)) {
            ByteBuffer buf = ByteBuffer.wrap(data);
            while (buf.hasRemaining()) {
                int n = ch.write(buf);
                assertTrue(n > 0);
            }
            assertArrayEquals(data, readAll(ch));
        }
    }

    @Test
    void readBeyondEofReturnsMinusOne() throws IOException {
        byte[] data = new byte[100];
        try (BlockBufferedChannel ch = openChannel(newFile(), enc(), true)) {
            ch.write(ByteBuffer.wrap(data));
            ch.position(100);
            assertEquals(-1, ch.read(ByteBuffer.allocate(10)));
            ch.position(10_000);
            assertEquals(-1, ch.read(ByteBuffer.allocate(10)));
        }
    }

    @Test
    void readWithEmptyBufferReturnsZero() throws IOException {
        try (BlockBufferedChannel ch = openChannel(newFile(), enc(), true)) {
            ch.write(ByteBuffer.wrap(new byte[100]));
            assertEquals(0, ch.read(ByteBuffer.allocate(0)));
        }
    }

    @Test
    void partialBlockWriteMergesWithExistingData() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) enc.plainBS()];
        Arrays.fill(data, (byte) 0x11);

        try (BlockBufferedChannel ch = openChannel(newFile(), enc, true)) {
            ch.write(ByteBuffer.wrap(data));
            ch.position(100);

            byte[] replacement = "REPLACED".getBytes();
            ch.write(ByteBuffer.wrap(replacement));

            byte[] read = readAll(ch);
            assertEquals(data.length, read.length);
            assertEquals(0x11, read[0]);
            assertEquals(0x11, read[99]);
            assertEquals(0x11, read[100 + replacement.length]);
            for (int i = 0; i < replacement.length; i++) {
                assertEquals(replacement[i], read[100 + i]);
            }
        }
    }

    @Test
    void writeIntoHolePadsWithZeros() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0x77);

        try (BlockBufferedChannel ch = openChannel(newFile(), enc, true)) {
            long offset = 5000;
            ch.position(offset);
            ch.write(ByteBuffer.wrap(data));

            byte[] read = readAll(ch);
            assertEquals(offset + data.length, read.length);
            for (int i = 0; i < offset; i++) {
                assertEquals(0, read[i], "hole byte " + i);
            }
            for (int i = 0; i < data.length; i++) {
                assertEquals(0x77, read[(int) offset + i]);
            }
        }
    }

    @Test
    void sparseWriteAfterPartialBlockKeepsFirstBlockReadable() throws IOException {
        ContentEnc enc = enc();
        byte[] head = new byte[100];
        Arrays.fill(head, (byte) 0x66);
        byte[] tail = new byte[50];
        Arrays.fill(tail, (byte) 0x55);

        try (BlockBufferedChannel ch = openChannel(newFile(), enc, true)) {
            ch.write(ByteBuffer.wrap(head));

            long offset = 9000;
            ch.position(offset);
            ch.write(ByteBuffer.wrap(tail));

            byte[] read = readAll(ch);
            assertEquals(offset + tail.length, read.length);
            for (int i = 0; i < head.length; i++) {
                assertEquals(0x66, read[i], "head byte " + i);
            }
            for (int i = head.length; i < offset; i++) {
                assertEquals(0, read[i], "hole byte " + i);
            }
            for (int i = 0; i < tail.length; i++) {
                assertEquals(0x55, read[(int) offset + i], "tail byte " + i);
            }
        }
    }

    @Test
    void sparseWriteAfterReadOfHoleBlockKeepsPartialBlockReadable() throws IOException {
        ContentEnc enc = enc();
        byte[] head = new byte[100];
        Arrays.fill(head, (byte) 0x66);
        byte[] tail = new byte[50];
        Arrays.fill(tail, (byte) 0x55);

        try (BlockBufferedChannel ch = openChannel(newFile(), enc, true)) {
            ch.write(ByteBuffer.wrap(head));

            long offset = 9000;
            ch.position(offset);
            // Reading at a hole position buffers the (empty) hole block, so the
            // following write targets an already-buffered block.
            assertEquals(-1, ch.read(ByteBuffer.allocate(10)));
            ch.write(ByteBuffer.wrap(tail));

            byte[] read = readAll(ch);
            assertEquals(offset + tail.length, read.length);
            for (int i = 0; i < head.length; i++) {
                assertEquals(0x66, read[i], "head byte " + i);
            }
            for (int i = head.length; i < offset; i++) {
                assertEquals(0, read[i], "hole byte " + i);
            }
            for (int i = 0; i < tail.length; i++) {
                assertEquals(0x55, read[(int) offset + i], "tail byte " + i);
            }
        }
    }

    @Test
    void writeIntoHoleWithinBufferedBlockZeroesGap() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[4196];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 31);
        }

        try (BlockBufferedChannel ch = openChannel(newFile(), enc, true)) {
            ByteBuffer buf = ByteBuffer.wrap(data);
            while (buf.hasRemaining()) {
                assertTrue(ch.write(buf) > 0);
            }

            // Block 1 holds 100 valid bytes (offsets 0..99). Writing a single
            // byte at block offset 2000 must zero the gap 100..1999 instead of
            // leaking the previous block's plaintext.
            ch.position(6096);
            ch.write(ByteBuffer.wrap(new byte[]{0x42}));

            byte[] read = readAll(ch);
            assertEquals(6097, read.length);
            for (int i = 0; i < data.length; i++) {
                assertEquals(data[i], read[i], "data byte " + i);
            }
            for (int i = 4196; i < 6096; i++) {
                assertEquals(0, read[i], "hole byte " + i);
            }
            assertEquals(0x42, read[6096]);
        }
    }

    @Test
    void truncateGrowPadsWithZeros() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/f.txt");
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0x22);

        h.fileManager.write("/f.txt", 0, data);
        h.fileManager.truncate("/f.txt", 1000);

        byte[] read = h.fileManager.readAll("/f.txt");
        assertEquals(1000, read.length);
        for (int i = 0; i < 100; i++) {
            assertEquals(0x22, read[i]);
        }
        for (int i = 100; i < 1000; i++) {
            assertEquals(0, read[i]);
        }
    }

    @Test
    void truncateShrink() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) (enc.plainBS() * 2)];
        Arrays.fill(data, (byte) 0x33);

        try (BlockBufferedChannel ch = openChannel(newFile(), enc, true)) {
            ByteBuffer buf = ByteBuffer.wrap(data);
            while (buf.hasRemaining()) {
                assertTrue(ch.write(buf) > 0);
            }
            ch.truncate(1000);

            assertEquals(1000, ch.size());
            byte[] read = readAll(ch);
            assertEquals(1000, read.length);
            for (int i = 0; i < 1000; i++) {
                assertEquals(0x33, read[i]);
            }
        }
    }

    @Test
    void streamingWriteAcrossBlocks() throws IOException {
        byte[] key = Keys.randomBytes(Constants.KEY_LEN);
        ContentEnc enc = new ContentEnc(key, Constants.DEFAULT_IV_BITS / 8);
        byte[] data = new byte[(int) (enc.plainBS() * 2 + 1000)];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 7);
        }

        Path p = newFile();
        try (BlockBufferedChannel ch = openChannel(p,
                new ContentEnc(key, Constants.DEFAULT_IV_BITS / 8), true)) {
            int pos = 0;
            while (pos < data.length) {
                int chunk = Math.min(777, data.length - pos);
                ByteBuffer bb = ByteBuffer.wrap(data, pos, chunk);
                while (bb.hasRemaining()) {
                    int n = ch.write(bb);
                    assertTrue(n > 0);
                    pos += n;
                }
            }
        }

        try (BlockBufferedChannel ch = openChannel(p,
                new ContentEnc(key, Constants.DEFAULT_IV_BITS / 8), false)) {
            assertArrayEquals(data, readAll(ch));
        }
    }

    @Test
    void readOnlyRejectsWrite() throws IOException {
        Path p = newFile();
        try (BlockBufferedChannel ch = openChannel(p, enc(), true)) {
            ch.write(ByteBuffer.wrap(new byte[10]));
        }
        try (BlockBufferedChannel ch = openChannel(p, enc(), false)) {
            assertThrows(Exception.class, () -> ch.write(ByteBuffer.wrap(new byte[10])));
        }
    }

    @Test
    void positionAndSizeTracking() throws IOException {
        byte[] data = new byte[100];
        try (BlockBufferedChannel ch = openChannel(newFile(), enc(), true)) {
            ch.write(ByteBuffer.wrap(data));
            assertEquals(100, ch.position());
            assertEquals(100, ch.size());

            ch.position(50);
            ByteBuffer buf = ByteBuffer.allocate(10);
            assertEquals(10, ch.read(buf));
            assertEquals(60, ch.position());
        }
    }

    @Test
    void unflushedWriteIsVisibleToSizeAndStat() throws IOException {
        ManagerHarness h = ManagerHarness.encrypted();
        h.fileManager.createFile("/f.txt");

        try (SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true);
             BlockBufferedChannel ch = cf.newChannel(0, true)) {
            // A single short block stays buffered and is not yet written
            // through, but size and stat must still report its plaintext size.
            ch.write(ByteBuffer.wrap(new byte[100]));
            assertEquals(100, ch.size());
            assertEquals(100L, h.fileManager.stat("/f.txt").size());
        }
    }
}
