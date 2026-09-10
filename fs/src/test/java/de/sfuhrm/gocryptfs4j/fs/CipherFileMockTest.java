package de.sfuhrm.gocryptfs4j.fs;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.FileHeader;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests {@link CipherFile} against a mocked {@link FileChannel} to exercise
 * conditions that are hard to produce with a real file (partial reads/writes,
 * delegation of close, empty-file short-circuits).
 */
class CipherFileMockTest {

    private static ContentEnc enc() {
        return new ContentEnc(Keys.randomBytes(Constants.KEY_LEN), Constants.DEFAULT_IV_BITS / 8);
    }

    private static CipherFile newCipherFile(FileChannel channel, ContentEnc enc) throws Exception {
        Constructor<CipherFile> ctor = CipherFile.class.getDeclaredConstructor(FileChannel.class, ContentEnc.class);
        ctor.setAccessible(true);
        return ctor.newInstance(channel, enc);
    }

    @Test
    void readOnEmptyFileReturnsMinusOneWithoutReading() throws Exception {
        FileChannel channel = mock(FileChannel.class);
        when(channel.size()).thenReturn(0L);
        CipherFile cf = newCipherFile(channel, enc());

        assertEquals(-1, cf.read(ByteBuffer.allocate(100), 0));
        verify(channel, never()).read(any(ByteBuffer.class), anyLong());
    }

    @Test
    void fileIdParsesHeaderDespitePartialReads() throws Exception {
        byte[] header = FileHeader.random().pack();
        FileChannel channel = mock(FileChannel.class);
        when(channel.size()).thenReturn((long) header.length);
        when(channel.read(any(ByteBuffer.class), anyLong())).thenAnswer(inv -> {
            ByteBuffer bb = inv.getArgument(0);
            long pos = inv.getArgument(1);
            if (pos >= header.length) {
                return -1;
            }
            int n = (int) Math.min(2, header.length - pos);
            bb.put(header, (int) pos, n);
            return n;
        });
        CipherFile cf = newCipherFile(channel, enc());

        byte[] id = cf.fileId();

        assertArrayEquals(FileHeader.parse(header).id(), id);
        verify(channel, atLeast(2)).read(any(ByteBuffer.class), anyLong());
    }

    @Test
    void writeHandlesPartialChannelWrites() throws Exception {
        FileChannel channel = mock(FileChannel.class);
        when(channel.size()).thenReturn(0L);
        when(channel.write(any(ByteBuffer.class), anyLong())).thenAnswer(inv -> {
            ByteBuffer bb = inv.getArgument(0);
            int n = Math.min(2, bb.remaining());
            bb.position(bb.position() + n);
            return n;
        });
        ContentEnc enc = enc();
        CipherFile cf = newCipherFile(channel, enc);

        byte[] data = new byte[(int) enc.plainBS];
        Arrays.fill(data, (byte) 0x33);
        int written = cf.write(ByteBuffer.wrap(data), 0);

        assertEquals(data.length, written);
        verify(channel, atLeast(2)).write(any(ByteBuffer.class), anyLong());
        assertEquals(Constants.HEADER_ID_LEN, cf.fileId().length);
    }

    @Test
    void plainSizeDelegatesToChannelSize() throws Exception {
        FileChannel channel = mock(FileChannel.class);
        ContentEnc enc = enc();
        when(channel.size()).thenReturn(Constants.HEADER_LEN + enc.cipherBS);
        CipherFile cf = newCipherFile(channel, enc());

        assertEquals(enc.plainBS, cf.plainSize());
        verify(channel).size();
    }
}
