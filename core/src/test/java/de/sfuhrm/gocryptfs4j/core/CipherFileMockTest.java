package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.FileHeader;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests {@link CipherFile} against a mocked {@link CipherChannel} to exercise
 * conditions that are hard to produce with a real file (partial reads/writes,
 * delegation of close, empty-file short-circuits).
 */
class CipherFileMockTest {

    private static ContentEnc enc() {
        return new ContentEnc(Keys.randomBytes(Constants.KEY_LEN), Constants.DEFAULT_IV_BITS / 8);
    }

    private static CipherFile newCipherFile(CipherChannel channel, ContentEnc enc) throws Exception {
        Constructor<CipherFile> ctor = CipherFile.class.getDeclaredConstructor(CipherChannel.class, ContentEnc.class);
        ctor.setAccessible(true);
        return ctor.newInstance(channel, enc);
    }

    @Test
    void readBlockOnEmptyFileReturnsZeroWithoutReading() throws Exception {
        CipherChannel channel = mock(CipherChannel.class);
        when(channel.size()).thenReturn(0L);
        CipherFile cf = newCipherFile(channel, enc());

        assertEquals(0, cf.readBlock(0, new byte[100], 0));
        verify(channel, never()).read(any(ByteBuffer.class));
    }

    @Test
    void fileIdParsesHeaderDespitePartialReads() throws Exception {
        byte[] header = FileHeader.random().pack();
        CipherChannel channel = mock(CipherChannel.class);
        when(channel.size()).thenReturn((long) header.length);
        long[] pos = {0};
        when(channel.position(anyLong())).thenAnswer(inv -> {
            pos[0] = inv.getArgument(0);
            return channel;
        });
        when(channel.read(any(ByteBuffer.class))).thenAnswer(inv -> {
            ByteBuffer bb = inv.getArgument(0);
            long p = pos[0];
            if (p >= header.length) {
                return -1;
            }
            int n = (int) Math.min(2, header.length - p);
            bb.put(header, (int) p, n);
            pos[0] = p + n;
            return n;
        });
        CipherFile cf = newCipherFile(channel, enc());

        byte[] id = cf.fileId();

        assertArrayEquals(FileHeader.parse(header).id(), id);
        verify(channel, atLeast(2)).read(any(ByteBuffer.class));
    }

    @Test
    void writeBlockHandlesPartialChannelWrites() throws Exception {
        CipherChannel channel = mock(CipherChannel.class);
        when(channel.size()).thenReturn(0L);
        long[] pos = {0};
        when(channel.position(anyLong())).thenAnswer(inv -> {
            pos[0] = inv.getArgument(0);
            return channel;
        });
        when(channel.write(any(ByteBuffer.class))).thenAnswer(inv -> {
            ByteBuffer bb = inv.getArgument(0);
            int n = Math.min(2, bb.remaining());
            bb.position(bb.position() + n);
            pos[0] += n;
            return n;
        });
        ContentEnc enc = enc();
        CipherFile cf = newCipherFile(channel, enc);

        byte[] data = new byte[(int) enc.plainBS()];
        Arrays.fill(data, (byte) 0x33);
        cf.writeBlock(0, data, 0, data.length);

        verify(channel, atLeast(2)).write(any(ByteBuffer.class));
        assertEquals(Constants.HEADER_ID_LEN, cf.fileId().length);
    }

    @Test
    void plainSizeDelegatesToChannelSize() throws Exception {
        CipherChannel channel = mock(CipherChannel.class);
        ContentEnc enc = enc();
        when(channel.size()).thenReturn(Constants.HEADER_LEN + enc.cipherBS());
        CipherFile cf = newCipherFile(channel, enc());

        assertEquals(enc.plainBS(), cf.plainSize());
        verify(channel).size();
    }

    @Test
    void closeForcesWritableChannelBeforeClosing() throws Exception {
        CipherChannel channel = mock(CipherChannel.class);
        when(channel.isOpen()).thenReturn(true);
        CipherFile cf = CipherFile.open(channel, enc(), true);

        cf.close();

        verify(channel).force(true);
        verify(channel).close();
    }

    @Test
    void closeReadOnlyDoesNotForce() throws Exception {
        CipherChannel channel = mock(CipherChannel.class);
        CipherFile cf = CipherFile.open(channel, enc(), false);

        cf.close();

        verify(channel, never()).force(anyBoolean());
        verify(channel).close();
    }

    @Test
    void truncateBlockAlignedDoesNotRewriteBlocks() throws Exception {
        ContentEnc enc = enc();
        byte[] header = FileHeader.random().pack();
        CipherChannel channel = mock(CipherChannel.class);
        when(channel.size()).thenReturn(Constants.HEADER_LEN + 2 * enc.cipherBS());
        long[] pos = {0};
        when(channel.position(anyLong())).thenAnswer(inv -> {
            pos[0] = inv.getArgument(0);
            return channel;
        });
        when(channel.read(any(ByteBuffer.class))).thenAnswer(inv -> {
            ByteBuffer bb = inv.getArgument(0);
            if (pos[0] >= header.length) {
                return -1;
            }
            int n = (int) Math.min(bb.remaining(), header.length - pos[0]);
            bb.put(header, (int) pos[0], n);
            pos[0] += n;
            return n;
        });
        CipherFile cf = newCipherFile(channel, enc);

        cf.truncate(enc.plainBS());

        verify(channel, never()).write(any(ByteBuffer.class));
        verify(channel).truncate(enc.blockNoToCipherOff(1));
    }

    @Test
    void writeBlockBeyondEofLeavesHoleBlocks() throws Exception {
        ContentEnc enc = enc();
        CipherChannel channel = mock(CipherChannel.class);
        when(channel.size()).thenReturn(0L);
        long[] pos = {0};
        List<Long> writeOffsets = new ArrayList<>();
        when(channel.position(anyLong())).thenAnswer(inv -> {
            pos[0] = inv.getArgument(0);
            return channel;
        });
        when(channel.write(any(ByteBuffer.class))).thenAnswer(inv -> {
            ByteBuffer bb = inv.getArgument(0);
            writeOffsets.add(pos[0]);
            int n = bb.remaining();
            bb.position(bb.position() + n);
            pos[0] += n;
            return n;
        });

        CipherFile cf = newCipherFile(channel, enc);

        long blockNo = 1000;
        cf.writeBlock(blockNo, new byte[]{0x11}, 0, 1);
        cf.force(false);

        // Only the header and the final block are written; the blocks in
        // between stay holes rather than being materialized as zero blocks.
        assertEquals(2, writeOffsets.size());
        assertEquals(0L, writeOffsets.get(0));
        assertEquals(enc.blockNoToCipherOff(blockNo), writeOffsets.get(1));
    }
}
