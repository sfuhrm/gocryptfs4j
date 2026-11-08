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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FlushFailureTest {

    @Test
    void closingLastHandleClosesFileAndWipesCacheWhenFlushFails() throws Exception {
        FailingWriteStore store = new FailingWriteStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.fileManager.createFile("/f.txt");

        SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true);
        SharedCipherFile.Entry entry = entryOf(cf);
        BlockBufferedChannel ch = cf.newChannel(0, true);
        ch.write(ByteBuffer.wrap(new byte[100]));
        BlockCache cache = cacheOf(ch);

        store.failWrites = true;
        assertThrows(IOException.class, ch::close);
        assertThrows(IOException.class, cf::close);

        assertFalse(store.channels.get(0).isOpen(), "the file descriptor must be closed");
        for (byte b : blockOf(cache)) {
            assertEquals(0, b, "buffered plaintext must be wiped");
        }
        assertNotNull(entry.failure, "the failed entry must be marked");
    }

    @Test
    void lastCloseFailureStaysVisibleAcrossSizeStatAndReopen() throws Exception {
        FailingWriteStore store = new FailingWriteStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.fileManager.createFile("/f.txt");

        SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true);
        BlockBufferedChannel ch = cf.newChannel(0, true);
        ch.write(ByteBuffer.wrap(new byte[100]));

        store.failWrites = true;
        assertThrows(IOException.class, ch::close);
        assertThrows(IOException.class, cf::close);

        store.failWrites = false;
        assertThrows(IOException.class, () -> h.fileManager.size("/f.txt"),
                "a later size must report the lost write");
        assertThrows(IOException.class, () -> h.fileManager.stat("/f.txt"),
                "a later stat must report the lost write");
        assertThrows(IOException.class,
                () -> h.fileManager.openCipherFile("/f.txt", false),
                "a reopen must report the lost write");

        // Deleting the damaged file is the explicit way to discard the sticky
        // failure and start over.
        h.fileManager.delete("/f.txt");
        h.fileManager.createFile("/f.txt");
        assertEquals(0, h.fileManager.readAll("/f.txt").length);
    }

    @Test
    void transientLastCloseFailureIsRetriedBeforeWiping() throws Exception {
        FailingWriteStore store = new FailingWriteStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.fileManager.createFile("/f.txt");

        SharedCipherFile cf = h.fileManager.openCipherFile("/f.txt", true, SyncPolicy.NONE);
        BlockBufferedChannel ch = cf.newChannel(0, true);
        byte[] payload = new byte[100];
        java.util.Arrays.fill(payload, (byte) 0x5a);
        ch.write(ByteBuffer.wrap(payload));

        store.failNextWriteOnly = true;
        ch.close();
        cf.close();

        byte[] read = h.fileManager.readAll("/f.txt");
        assertEquals(payload.length, read.length);
        assertEquals(0x5a, read[0], "the retried write must be durable");
    }

    @Test
    void failedFlushKeepsBlockForAnotherOpenHandleToRetry() throws Exception {
        FailingWriteStore store = new FailingWriteStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.fileManager.createFile("/f.txt");

        SharedCipherFile a = h.fileManager.openCipherFile("/f.txt", true);
        BlockBufferedChannel ca = a.newChannel(0, true);
        byte[] payload = new byte[100];
        java.util.Arrays.fill(payload, (byte) 0x5a);
        ca.write(ByteBuffer.wrap(payload));
        BlockCache cache = cacheOf(ca);

        SharedCipherFile b = h.fileManager.openCipherFile("/f.txt", true);

        store.failWrites = true;
        assertThrows(IOException.class, ca::close);
        assertEquals(0x5a, blockOf(cache)[0], "the dirty block must be retained for a retry");

        store.failWrites = false;
        b.close();

        byte[] read = h.fileManager.readAll("/f.txt");
        assertEquals(payload.length, read.length);
        assertEquals(0x5a, read[0]);
    }

    @Test
    void flushFailureDoesNotStopRemainingEntries() throws Exception {
        FailingWriteStore store = new FailingWriteStore();
        ManagerHarness h = ManagerHarness.encrypted(store);
        h.fileManager.createFile("/a.txt");
        h.fileManager.createFile("/b.txt");

        SharedCipherFile a = h.fileManager.openCipherFile("/a.txt", true);
        BlockBufferedChannel ca = a.newChannel(0, true);
        ca.write(ByteBuffer.wrap(new byte[100]));
        SharedCipherFile b = h.fileManager.openCipherFile("/b.txt", true);
        BlockBufferedChannel cb = b.newChannel(0, true);
        cb.write(ByteBuffer.wrap(new byte[100]));

        try {
            store.failWrites = true;
            IOException failure = assertThrows(IOException.class,
                    () -> h.fileManager.flushSharedFiles());
            assertEquals(1, failure.getSuppressed().length,
                    "the failure of the second entry must be attached");
        } finally {
            store.failWrites = false;
            ca.close();
            cb.close();
        }
    }

    private static SharedCipherFile.Entry entryOf(SharedCipherFile cf) throws Exception {
        Field field = SharedCipherFile.class.getDeclaredField("entry");
        field.setAccessible(true);
        return (SharedCipherFile.Entry) field.get(cf);
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

    private static final class FailingWriteStore implements CipherStore {

        private final CipherStore delegate = new MapCipherStore();
        private final List<FailingChannel> channels = new ArrayList<>();
        private boolean failWrites;
        private boolean failNextWriteOnly;

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
        private final FailingWriteStore store;

        private FailingChannel(CipherChannel delegate, FailingWriteStore store) {
            this.delegate = delegate;
            this.store = store;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            return delegate.read(dst);
        }

        @Override
        public int write(ByteBuffer src) throws IOException {
            if (store.failWrites) {
                throw new IOException("simulated write failure");
            }
            if (store.failNextWriteOnly) {
                store.failNextWriteOnly = false;
                throw new IOException("simulated transient write failure");
            }
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
