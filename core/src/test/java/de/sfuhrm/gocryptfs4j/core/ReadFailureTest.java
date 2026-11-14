package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.memory.MapCipherStore;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ReadFailureTest {

    @Test
    void failedBlockReadInvalidatesCacheInsteadOfReturningStaleBytes() throws Exception {
        FailingReadStore store = new FailingReadStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.fileManager.createFile("/f.txt");

        SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true);
        BlockBufferedChannel ch = cf.newChannel(0, true);
        BlockCache cache = cacheOf(ch);
        int blockSize = cache.blockSize();

        byte[] block0 = filled(blockSize, (byte) 0x11);
        byte[] block1 = filled(100, (byte) 0x22);
        ch.write(ByteBuffer.wrap(block0));
        ch.write(ByteBuffer.wrap(block1));
        ch.flush();

        // Cache block 0 (clean) by reading a byte of it.
        ch.position(0);
        ByteBuffer first = ByteBuffer.allocate(1);
        assertEquals(1, ch.read(first));
        assertEquals(0x11, first.get(0));

        // Reading block 1 now fails while the block is being loaded.
        store.failReads = true;
        ch.position(blockSize);
        assertThrows(IOException.class, () -> ch.read(ByteBuffer.allocate(100)));

        // The cache must be invalidated and the plaintext buffer wiped, so a
        // failed load cannot be mistaken for the requested block.
        assertEquals(-1L, blockNoOf(cache));
        for (byte b : blockOf(cache)) {
            assertEquals(0, b, "buffered plaintext must be wiped");
        }

        // A retry must reload the real block, not hand back stale block 0 bytes.
        store.failReads = false;
        ch.position(blockSize);
        ByteBuffer retry = ByteBuffer.allocate(100);
        assertEquals(100, ch.read(retry));
        assertEquals(0x22, retry.get(0), "the retried read must return block 1");
    }

    @Test
    void failedBlockReadDoesNotOverwriteOnDiskBlockOnNextWrite() throws Exception {
        FailingReadStore store = new FailingReadStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.fileManager.createFile("/f.txt");

        SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true);
        BlockBufferedChannel ch = cf.newChannel(0, true);
        BlockCache cache = cacheOf(ch);
        int blockSize = cache.blockSize();

        // Three full blocks, so block 1 is not the final partial block and the
        // write path below cannot trigger a zero-pad.
        ch.write(ByteBuffer.wrap(filled(blockSize, (byte) 0x11)));
        ch.write(ByteBuffer.wrap(filled(blockSize, (byte) 0x22)));
        ch.write(ByteBuffer.wrap(filled(blockSize, (byte) 0x33)));
        ch.flush();

        // Cache block 0 (clean).
        ch.position(0);
        assertEquals(1, ch.read(ByteBuffer.allocate(1)));

        // Fail the load of block 1, then patch a few bytes of it.
        store.failReads = true;
        ch.position(blockSize);
        assertThrows(IOException.class, () -> ch.read(ByteBuffer.allocate(100)));

        store.failReads = false;
        ch.position(blockSize);
        assertEquals(50, ch.write(ByteBuffer.wrap(filled(50, (byte) 0x44))));
        ch.flush();

        // The untouched tail of block 1 must survive: writing over the stale
        // buffer would destroy the 0x22 bytes still on disk.
        ch.position(blockSize);
        ByteBuffer buf = ByteBuffer.allocate(100);
        assertEquals(100, ch.read(buf));
        assertEquals(0x44, buf.get(0));
        assertEquals(0x22, buf.get(50), "bytes past the patch must be preserved");
    }

    private static byte[] filled(int len, byte value) {
        byte[] b = new byte[len];
        Arrays.fill(b, value);
        return b;
    }

    private static BlockCache cacheOf(BlockBufferedChannel ch) throws Exception {
        Field field = BlockBufferedChannel.class.getDeclaredField("cache");
        field.setAccessible(true);
        return (BlockCache) field.get(ch);
    }

    private static byte[] blockOf(BlockCache cache) throws Exception {
        Field field = BlockCache.class.getDeclaredField("block");
        field.setAccessible(true);
        return (byte[]) field.get(cache);
    }

    private static long blockNoOf(BlockCache cache) throws Exception {
        Field field = BlockCache.class.getDeclaredField("blockNo");
        field.setAccessible(true);
        return field.getLong(cache);
    }

    private static final class FailingReadStore implements CipherStore {

        private final CipherStore delegate = new MapCipherStore();
        private final List<FailingChannel> channels = new ArrayList<>();
        private boolean failReads;

        @Override
        public String root() {
            return delegate.root();
        }

        @Override
        public byte[] readSmall(String name, int maxBytes) throws IOException {
            return delegate.readSmall(name, maxBytes);
        }

        @Override
        public void writeSmall(String name, byte[] data, boolean overwrite) throws IOException {
            delegate.writeSmall(name, data, overwrite);
        }

        @Override
        public CipherNode stat(String name) throws IOException {
            return delegate.stat(name);
        }

        @Override
        public List<CipherNode> list(String dir) throws IOException {
            return delegate.list(dir);
        }

        @Override
        public void createFile(String name) throws IOException {
            delegate.createFile(name);
        }

        @Override
        public void mkdir(String name) throws IOException {
            delegate.mkdir(name);
        }

        @Override
        public void delete(String name) throws IOException {
            delegate.delete(name);
        }

        @Override
        public void rename(String from, String to, boolean replaceExisting) throws IOException {
            delegate.rename(from, to, replaceExisting);
        }

        @Override
        public void createSymlink(String name, String target) throws IOException {
            delegate.createSymlink(name, target);
        }

        @Override
        public String readSymlink(String name) throws IOException {
            return delegate.readSymlink(name);
        }

        @Override
        public void setTimes(String name, @Nullable FileTime lastModifiedTime,
                             @Nullable FileTime lastAccessTime,
                             @Nullable FileTime creationTime) throws IOException {
            delegate.setTimes(name, lastModifiedTime, lastAccessTime, creationTime);
        }

        @Override
        public CipherChannel open(String name, boolean writable) throws IOException {
            FailingChannel channel = new FailingChannel(delegate.open(name, writable), this);
            channels.add(channel);
            return channel;
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }

    private static final class FailingChannel implements CipherChannel {

        private final CipherChannel delegate;
        private final FailingReadStore store;

        private FailingChannel(CipherChannel delegate, FailingReadStore store) {
            this.delegate = delegate;
            this.store = store;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            if (store.failReads) {
                throw new IOException("simulated read failure");
            }
            return delegate.read(dst);
        }

        @Override
        public int write(ByteBuffer src) throws IOException {
            return delegate.write(src);
        }

        @Override
        public long position() throws IOException {
            return delegate.position();
        }

        @Override
        public SeekableByteChannel position(long newPosition) throws IOException {
            return delegate.position(newPosition);
        }

        @Override
        public long size() throws IOException {
            return delegate.size();
        }

        @Override
        public SeekableByteChannel truncate(long size) throws IOException {
            return delegate.truncate(size);
        }

        @Override
        public boolean isOpen() {
            return delegate.isOpen();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        @Override
        public void force(boolean metaData) throws IOException {
            delegate.force(metaData);
        }
    }
}
