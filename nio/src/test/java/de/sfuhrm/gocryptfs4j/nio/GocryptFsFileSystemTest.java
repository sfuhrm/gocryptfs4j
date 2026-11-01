package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import de.sfuhrm.gocryptfs4j.store.memory.MapCipherStore;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchService;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Tests for the basic properties and lifecycle of {@link GocryptFsFileSystem}. */
class GocryptFsFileSystemTest {

    @TempDir
    Path tmp;

    @Test
    void properties() throws IOException {
        Path cipherDir = createCipherDir("props");
        try (FileSystem fs = new GocryptFsProvider().newFileSystem(cipherDir, "pw".toCharArray())) {
            assertTrue(fs.isOpen());
            assertEquals(Files.getFileStore(cipherDir).isReadOnly(), fs.isReadOnly());
            assertEquals("/", fs.getSeparator());
            assertNotNull(fs.provider());

            List<Path> roots = new ArrayList<>();
            fs.getRootDirectories().forEach(roots::add);
            assertEquals(1, roots.size());
            assertEquals("/", roots.get(0).toString());

            assertTrue(fs.getFileStores().iterator().hasNext());
            assertTrue(fs.supportedFileAttributeViews().contains("basic"));
            assertTrue(fs.toString().startsWith("gocryptfs://"));
        }
    }

    @Test
    void watchServiceLifecycle() throws IOException {
        Path cipherDir = createCipherDir("watch");
        FileSystem fs = new GocryptFsProvider().newFileSystem(cipherDir, "pw".toCharArray());
        try (WatchService watcher = fs.newWatchService()) {
            assertNotNull(watcher);
        }
        fs.close();
        fs.close();
        assertFalse(fs.isOpen());
        assertThrows(ClosedFileSystemException.class, fs::newWatchService);
    }

    @Test
    void closeClosesWatchServices() throws Exception {
        Path cipherDir = createCipherDir("watch-close");
        FileSystem fs = new GocryptFsProvider().newFileSystem(cipherDir, "pw".toCharArray());
        WatchService watcher = fs.newWatchService();
        fs.getPath("/").register(watcher, StandardWatchEventKinds.ENTRY_CREATE);

        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread blocked = new Thread(() -> {
            try {
                watcher.take();
            } catch (Throwable t) {
                failure.set(t);
            }
        }, "watch-take");
        blocked.start();
        Thread.sleep(200L);

        fs.close();

        blocked.join(5000L);
        assertFalse(blocked.isAlive(), "thread blocked in take() must wake up on close");
        assertTrue(failure.get() instanceof ClosedWatchServiceException,
                "take() must fail with ClosedWatchServiceException but got " + failure.get());
    }

    @Test
    void closeReleasesBackingStore() throws IOException {
        TrackingStore store = new TrackingStore();
        GocryptFs core = GocryptFs.create(store, "pw".toCharArray());
        GocryptFsFileSystem fs = new GocryptFsFileSystem(
                new GocryptFsProvider(), store, core, "/cipher", false);

        assertFalse(store.isClosed());
        fs.close();
        assertTrue(store.isClosed(), "filesystem close must close the backing store");
    }

    @Test
    void urlDecode() {
        assertEquals("a/b", GocryptFsFileSystem.urlDecode("a%2Fb"));
        assertEquals("%zz", GocryptFsFileSystem.urlDecode("%zz"));
    }

    private Path createCipherDir(String name) throws IOException {
        Path cipherDir = tmp.resolve(name);
        Files.createDirectory(cipherDir);
        try (GocryptFs ignored = GocryptFs.create(new PathCipherStore(cipherDir), "pw".toCharArray())) {
            // empty filesystem
        }
        return cipherDir;
    }

    /** A {@link CipherStore} that records whether {@link #close()} was called. */
    private static final class TrackingStore implements CipherStore {

        private final MapCipherStore delegate = new MapCipherStore();
        private boolean closed;

        boolean isClosed() {
            return closed;
        }

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
        public void setTimes(String name, FileTime lastModifiedTime,
                             FileTime lastAccessTime, FileTime creationTime) throws IOException {
            delegate.setTimes(name, lastModifiedTime, lastAccessTime, creationTime);
        }

        @Override
        public CipherChannel open(String name, boolean writable) throws IOException {
            return delegate.open(name, writable);
        }

        @Override
        public void close() {
            closed = true;
            delegate.close();
        }
    }
}
