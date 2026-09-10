package de.sfuhrm.gocryptfs4j.fs;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class CipherFileTest {

    @TempDir
    Path tmp;

    private ContentEnc enc() {
        return new ContentEnc(Keys.randomBytes(Constants.KEY_LEN), Constants.DEFAULT_IV_BITS / 8);
    }

    private Path file() {
        return tmp.resolve("file.bin");
    }

    private Path newFile() throws IOException {
        Path p = file();
        Files.createFile(p);
        return p;
    }

    private static byte[] readAll(CipherFile cf) throws IOException {
        long size = cf.plainSize();
        ByteArrayOutputStream out = new ByteArrayOutputStream((int) size);
        long pos = 0;
        while (pos < size) {
            byte[] chunk = new byte[(int) Math.min(4096, size - pos)];
            ByteBuffer buf = ByteBuffer.wrap(chunk);
            int n = cf.read(buf, pos);
            if (n < 0) {
                break;
            }
            out.write(chunk, 0, n);
            pos += n;
        }
        return out.toByteArray();
    }

    @Test
    void emptyFileHasNullFileIdAndZeroSize() throws IOException {
        try (CipherFile cf = CipherFile.open(newFile(), enc(), true)) {
            assertNull(cf.fileId());
            assertEquals(0, cf.plainSize());
        }
    }

    @Test
    void writeAndReadRoundTripSingleBlock() throws IOException {
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0x5a);

        try (CipherFile cf = CipherFile.open(newFile(), enc(), true)) {
            assertEquals(data.length, cf.write(ByteBuffer.wrap(data), 0));
            assertEquals(data.length, cf.plainSize());
            assertArrayEquals(data, readAll(cf));
        }
    }

    @Test
    void writeAndReadRoundTripMultiBlock() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) (enc.plainBS * 2 + 100)];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 31);
        }

        try (CipherFile cf = CipherFile.open(newFile(), enc, true)) {
            assertEquals(data.length, cf.write(ByteBuffer.wrap(data), 0));
            assertArrayEquals(data, readAll(cf));
        }
    }

    @Test
    void readBeyondEofReturnsMinusOne() throws IOException {
        byte[] data = new byte[100];
        try (CipherFile cf = CipherFile.open(newFile(), enc(), true)) {
            cf.write(ByteBuffer.wrap(data), 0);

            assertEquals(-1, cf.read(ByteBuffer.allocate(10), 100));
            assertEquals(-1, cf.read(ByteBuffer.allocate(10), 10_000));
        }
    }

    @Test
    void readWithEmptyBufferReturnsZero() throws IOException {
        try (CipherFile cf = CipherFile.open(newFile(), enc(), true)) {
            cf.write(ByteBuffer.wrap(new byte[100]), 0);
            assertEquals(0, cf.read(ByteBuffer.allocate(0), 0));
        }
    }

    @Test
    void partialBlockWriteMergesWithExistingData() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) enc.plainBS];
        Arrays.fill(data, (byte) 0x11);

        try (CipherFile cf = CipherFile.open(newFile(), enc, true)) {
            cf.write(ByteBuffer.wrap(data), 0);

            byte[] replacement = "REPLACED".getBytes();
            cf.write(ByteBuffer.wrap(replacement), 100);

            byte[] read = readAll(cf);
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

        try (CipherFile cf = CipherFile.open(newFile(), enc, true)) {
            long offset = 5000;
            cf.write(ByteBuffer.wrap(data), offset);

            byte[] read = readAll(cf);
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
    void truncateGrowPadsWithZeros() throws IOException {
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0x22);

        try (CipherFile cf = CipherFile.open(newFile(), enc(), true)) {
            cf.write(ByteBuffer.wrap(data), 0);
            cf.truncate(1000);

            assertEquals(1000, cf.plainSize());
            byte[] read = readAll(cf);
            assertEquals(1000, read.length);
            for (int i = 0; i < 100; i++) {
                assertEquals(0x22, read[i]);
            }
            for (int i = 100; i < 1000; i++) {
                assertEquals(0, read[i]);
            }
        }
    }

    @Test
    void truncateShrink() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) (enc.plainBS + 500)];
        Arrays.fill(data, (byte) 0x33);

        try (CipherFile cf = CipherFile.open(newFile(), enc, true)) {
            cf.write(ByteBuffer.wrap(data), 0);
            cf.truncate(1000);

            assertEquals(1000, cf.plainSize());
            byte[] read = readAll(cf);
            assertEquals(1000, read.length);
            for (int i = 0; i < 1000; i++) {
                assertEquals(0x33, read[i]);
            }
        }
    }

    @Test
    void truncateToZero() throws IOException {
        byte[] data = new byte[100];
        try (CipherFile cf = CipherFile.open(newFile(), enc(), true)) {
            cf.write(ByteBuffer.wrap(data), 0);
            cf.truncate(0);

            assertEquals(0, cf.plainSize());
            assertNull(cf.fileId());
        }
    }

    @Test
    void fileIdIsRandomAndPersistsAcrossReopen() throws IOException {
        Path p = newFile();
        byte[] id;
        try (CipherFile cf = CipherFile.open(p, enc(), true)) {
            cf.write(ByteBuffer.wrap(new byte[100]), 0);
            id = cf.fileId();
        }

        assertEquals(Constants.HEADER_ID_LEN, id.length);
        boolean nonZero = false;
        for (byte b : id) {
            if (b != 0) {
                nonZero = true;
                break;
            }
        }
        assertTrue(nonZero, "file id should not be all-zero");

        try (CipherFile cf = CipherFile.open(p, enc(), false)) {
            assertArrayEquals(id, cf.fileId());
        }
    }

    @Test
    void readOnlyRejectsWrite() throws IOException {
        Path p = newFile();
        try (CipherFile cf = CipherFile.open(p, enc(), true)) {
            cf.write(ByteBuffer.wrap(new byte[10]), 0);
        }
        try (CipherFile cf = CipherFile.open(p, enc(), false)) {
            assertThrows(Exception.class, () -> cf.write(ByteBuffer.wrap(new byte[10]), 0));
        }
    }
}
