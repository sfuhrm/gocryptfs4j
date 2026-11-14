package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
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

    private static CipherFile open(Path p, ContentEnc enc, boolean writable) throws IOException {
        PathCipherStore store = new PathCipherStore(p.getParent());
        CipherChannel channel = store.open(p.toAbsolutePath().toString(), writable);
        return CipherFile.open(channel, enc, writable);
    }

    @Test
    void emptyFileHasNullFileIdAndZeroSize() throws IOException {
        try (CipherFile cf = open(newFile(), enc(), true)) {
            assertNull(cf.fileId());
            assertEquals(0, cf.plainSize());
        }
    }

    @Test
    void writeBlockAndReadBlockRoundTrip() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) enc.plainBS];
        Arrays.fill(data, (byte) 0x5a);

        try (CipherFile cf = open(newFile(), enc, true)) {
            cf.writeBlock(0, data, 0, data.length);
            assertEquals(data.length, cf.plainSize());

            byte[] out = new byte[(int) enc.plainBS];
            assertEquals(data.length, cf.readBlock(0, out, 0));
            assertArrayEquals(data, out);
        }
    }

    @Test
    void closingFileWipesItsContentKey() throws IOException {
        ContentEnc enc = enc();
        try (CipherFile cf = open(newFile(), enc, true)) {
            cf.writeBlock(0, new byte[10], 0, 10);
        }
        assertThrows(IllegalStateException.class,
                () -> enc.encryptBlock(new byte[10], 0, null));
    }

    @Test
    void closingOneFileKeepsOtherOpenFileUsable() throws IOException {
        byte[] key = Keys.randomBytes(Constants.KEY_LEN);
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0x33);

        Path a = tmp.resolve("a.bin");
        Files.createFile(a);
        Path b = tmp.resolve("b.bin");
        Files.createFile(b);

        CipherFile first = open(a, new ContentEnc(key, Constants.DEFAULT_IV_BITS / 8), true);
        CipherFile second = open(b, new ContentEnc(key, Constants.DEFAULT_IV_BITS / 8), true);
        try {
            first.writeBlock(0, data, 0, data.length);
            first.close();
            second.writeBlock(0, data, 0, data.length);
            byte[] out = new byte[data.length];
            assertEquals(data.length, second.readBlock(0, out, 0));
            assertArrayEquals(data, out);
        } finally {
            second.close();
        }
    }

    @Test
    void writeBlockPartialRoundTrip() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0x7e);

        try (CipherFile cf = open(newFile(), enc, true)) {
            cf.writeBlock(0, data, 0, data.length);
            assertEquals(data.length, cf.plainSize());

            byte[] out = new byte[(int) enc.plainBS];
            assertEquals(data.length, cf.readBlock(0, out, 0));
            assertArrayEquals(data, Arrays.copyOf(out, data.length));
        }
    }

    @Test
    void readBlockBeyondEofReturnsZero() throws IOException {
        ContentEnc enc = enc();
        try (CipherFile cf = open(newFile(), enc, true)) {
            cf.writeBlock(0, new byte[100], 0, 100);
            byte[] out = new byte[(int) enc.plainBS];
            assertEquals(0, cf.readBlock(10_000, out, 0));
        }
    }

    @Test
    void writeBlockBeyondEofLeavesHolesReadBackAsZeros() throws IOException {
        ContentEnc enc = enc();
        try (CipherFile cf = open(newFile(), enc, true)) {
            long blockNo = 1000;
            byte[] data = new byte[100];
            Arrays.fill(data, (byte) 0x77);
            cf.writeBlock(blockNo, data, 0, data.length);

            assertEquals(blockNo * enc.plainBS + data.length, cf.plainSize());
            byte[] hole = new byte[(int) enc.plainBS];
            assertEquals(enc.plainBS, cf.readBlock(blockNo - 1, hole, 0));
            assertArrayEquals(new byte[(int) enc.plainBS], hole);
        }
    }

    @Test
    void truncateToZero() throws IOException {
        try (CipherFile cf = open(newFile(), enc(), true)) {
            cf.writeBlock(0, new byte[100], 0, 100);
            cf.truncate(0);

            assertEquals(0, cf.plainSize());
            assertNull(cf.fileId());
        }
    }

    @Test
    void truncateToZeroRepairsTornHeader() throws IOException {
        ContentEnc enc = enc();
        Path p = newFile();
        // A torn write leaves a partial header: fewer bytes than HEADER_LEN,
        // which reports a plain size of 0 even though the file is not empty.
        Files.write(p, new byte[Constants.HEADER_LEN - 1]);

        try (CipherFile cf = open(p, enc, true)) {
            assertEquals(0, cf.plainSize(), "a torn header must report a zero plain size");

            cf.truncate(0);

            assertEquals(0, cf.plainSize());
            assertNull(cf.fileId());
        }

        assertEquals(0, Files.size(p), "truncate(0) must actually remove the torn header");
    }

    @Test
    void truncateShrink() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) (enc.plainBS + 500)];
        Arrays.fill(data, (byte) 0x33);

        try (CipherFile cf = open(newFile(), enc, true)) {
            cf.writeBlock(0, data, 0, (int) enc.plainBS);
            cf.writeBlock(1, data, (int) enc.plainBS, 500);
            assertEquals(data.length, cf.plainSize());

            cf.truncate(1000);

            assertEquals(1000, cf.plainSize());
            byte[] out = new byte[1000];
            int n = cf.readBlock(0, out, 0);
            assertEquals(1000, n);
            for (int i = 0; i < 1000; i++) {
                assertEquals(0x33, out[i]);
            }
        }
    }

    @Test
    void truncateToBlockBoundaryKeepsFullBlocks() throws IOException {
        ContentEnc enc = enc();
        int bs = (int) enc.plainBS;
        byte[] data = new byte[bs * 2 + 500];
        Arrays.fill(data, (byte) 0x44);

        try (CipherFile cf = open(newFile(), enc, true)) {
            cf.writeBlock(0, data, 0, bs);
            cf.writeBlock(1, data, bs, bs);
            cf.writeBlock(2, data, bs * 2, 500);
            assertEquals(data.length, cf.plainSize());

            cf.truncate(bs * 2L);

            assertEquals(bs * 2L, cf.plainSize());
            byte[] out = new byte[bs * 2];
            int n = cf.readBlock(0, out, 0);
            assertEquals(bs, n);
            n += cf.readBlock(1, out, bs);
            assertEquals(bs * 2, n);
            assertArrayEquals(Arrays.copyOf(data, bs * 2), out);
        }
    }

    @Test
    void tornTailThrowsIoExceptionNotUnchecked() throws IOException {
        ContentEnc enc = enc();
        Path p = newFile();
        try (CipherFile cf = open(p, enc, true)) {
            cf.writeBlock(0, new byte[(int) enc.plainBS], 0, (int) enc.plainBS);
            cf.force(false);
        }

        // Simulate a torn tail: cut the last block short of the nonce length.
        try (SeekableByteChannel ch = Files.newByteChannel(p, StandardOpenOption.WRITE)) {
            ch.truncate(Constants.HEADER_LEN + enc.ivLen - 1);
        }

        try (CipherFile cf = open(p, enc, false)) {
            byte[] out = new byte[(int) enc.plainBS];
            assertThrows(IOException.class, () -> cf.readBlock(0, out, 0));
        }
    }

    @Test
    void fileIdIsRandomAndPersistsAcrossReopen() throws IOException {
        Path p = newFile();
        byte[] id;
        try (CipherFile cf = open(p, enc(), true)) {
            cf.writeBlock(0, new byte[100], 0, 100);
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

        try (CipherFile cf = open(p, enc(), false)) {
            assertArrayEquals(id, cf.fileId());
        }
    }

    @Test
    void fileIdGetterReturnsACopy() throws IOException {
        ContentEnc enc = enc();
        byte[] data = new byte[256];
        Arrays.fill(data, (byte) 0x5a);

        try (CipherFile cf = open(newFile(), enc, true)) {
            cf.writeBlock(0, data, 0, data.length);

            byte[] id = cf.fileId();
            assertNotNull(id);
            byte[] copy = id.clone();

            // Corrupting the returned array must not change the id used as
            // additional authenticated data for subsequent operations.
            Arrays.fill(id, (byte) 0xFF);
            assertArrayEquals(copy, cf.fileId(), "fileId() must return a defensive copy");
            byte[] out = new byte[256];
            assertEquals(256, cf.readBlock(0, out, 0));
            assertArrayEquals(data, out);
        }
    }

    @Test
    void closeWipesScratchBuffers() throws Exception {
        ContentEnc enc = enc();
        byte[] data = new byte[(int) enc.plainBS];
        Arrays.fill(data, (byte) 0x42);

        CipherFile cf = open(newFile(), enc, true);
        cf.writeBlock(0, data, 0, data.length);
        byte[] out = new byte[(int) enc.plainBS];
        cf.readBlock(0, out, 0);

        assertHasNonZero(cf, "blockCipher");

        cf.close();

        assertArrayEquals(new byte[(int) enc.plainBS], (byte[]) field(cf, "blockPlain"));
        assertArrayEquals(new byte[(int) enc.cipherBS], (byte[]) field(cf, "blockCipher"));
    }

    private static Object field(Object target, String name) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }

    private static void assertHasNonZero(Object target, String name) throws Exception {
        byte[] a = (byte[]) field(target, name);
        assertNotNull(a, name + " should be populated before close");
        boolean nonZero = false;
        for (byte b : a) {
            if (b != 0) {
                nonZero = true;
                break;
            }
        }
        assertTrue(nonZero, name + " should contain non-zero data before close");
    }

    @Test
    void readOnlyRejectsWriteBlock() throws IOException {
        Path p = newFile();
        try (CipherFile cf = open(p, enc(), true)) {
            cf.writeBlock(0, new byte[10], 0, 10);
        }
        try (CipherFile cf = open(p, enc(), false)) {
            assertThrows(Exception.class, () -> cf.writeBlock(0, new byte[10], 0, 10));
        }
    }

    @Test
    void plainSizeReflectsExternalGrowth() throws IOException {
        ContentEnc enc = enc();
        Path p = newFile();

        try (CipherFile h1 = open(p, enc, true)) {
            h1.writeBlock(0, new byte[(int) enc.plainBS], 0, (int) enc.plainBS);
            h1.force(false);
            assertEquals(enc.plainBS, h1.plainSize());

            // A second handle grows the file behind h1's back.
            try (CipherFile h2 = open(p, enc, true)) {
                h2.writeBlock(1, new byte[(int) enc.plainBS], 0, (int) enc.plainBS);
            }

            // h1 must observe the grown size instead of a stale cached value.
            assertEquals(2 * enc.plainBS, h1.plainSize());
        }
    }

    @Test
    void emptyFileHandleObservesExternalWrite() throws IOException {
        ContentEnc enc = enc();
        Path p = newFile();
        byte[] data = new byte[100];
        Arrays.fill(data, (byte) 0x21);

        try (CipherFile reader = open(p, enc, true);
             CipherFile writer = open(p, enc, true)) {
            assertNull(reader.fileId(), "an empty file has no file id");
            assertEquals(0, reader.plainSize());

            writer.writeBlock(0, data, 0, data.length);

            // The reader must not have cached the empty state forever.
            assertNotNull(reader.fileId());
            assertEquals(data.length, reader.plainSize());
            byte[] out = new byte[(int) enc.plainBS];
            assertEquals(data.length, reader.readBlock(0, out, 0));
            assertArrayEquals(data, Arrays.copyOf(out, data.length));
        }
    }

    @Test
    void readRetriesAfterExternalTruncateAndRewrite() throws IOException {
        byte[] key = Keys.randomBytes(Constants.KEY_LEN);
        ContentEnc h1Enc = new ContentEnc(key, Constants.DEFAULT_IV_BITS / 8);
        ContentEnc h2Enc = new ContentEnc(key, Constants.DEFAULT_IV_BITS / 8);
        Path p = newFile();
        byte[] oldData = new byte[100];
        Arrays.fill(oldData, (byte) 0x11);
        byte[] newData = new byte[100];
        Arrays.fill(newData, (byte) 0x22);

        try (CipherFile h1 = open(p, h1Enc, true)) {
            h1.writeBlock(0, oldData, 0, oldData.length);
            byte[] out = new byte[(int) h1Enc.plainBS];
            assertEquals(oldData.length, h1.readBlock(0, out, 0));
            byte[] oldId = h1.fileId();

            byte[] newId;
            try (CipherFile h2 = open(p, h2Enc, true)) {
                h2.truncate(0);
                h2.writeBlock(0, newData, 0, newData.length);
                newId = h2.fileId();
            }
            assertFalse(Arrays.equals(oldId, newId), "rewrite must mint a new id");

            // h1 still has the old id cached. The read must re-read the header
            // once and retry instead of reporting every block as corrupt.
            assertEquals(newData.length, h1.readBlock(0, out, 0));
            assertArrayEquals(newData, Arrays.copyOf(out, newData.length));
            assertArrayEquals(newId, h1.fileId());
        }
    }
}
