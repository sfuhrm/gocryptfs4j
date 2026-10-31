package de.sfuhrm.gocryptfs4j.store.memory;

import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonWritableChannelException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory {@link CipherStore} backed by {@link Map}s.
 *
 * <p>The ciphertext tree is stored as three collections: regular files (blobs),
 * symbolic links and directory markers. File content is opened through a
 * {@link CipherChannel} that operates on an in-memory byte array, so the
 * encrypted-file layer works exactly as it does on a local or remote store.</p>
 *
 * <p>This class is thread-safe and is intended both as a test fixture and as a
 * minimal reference for writing a remote backend.</p>
 *
 * <p>Timestamps are not persisted: every entry reports the Unix epoch
 * ({@code 1970-01-01T00:00:00Z}) for its last-modified, last-access and
 * creation time, and {@link #setTimes(String, FileTime, FileTime, FileTime)}
 * is a no-op.</p>
 *
 * <p>{@link #open(String, boolean)} returns a channel that operates on a
 * snapshot copy of the file's content taken at open time. Two concurrently
 * open channels on the same file do not observe each other's writes, and when
 * both are writable the one closed last wins. This last-write-wins snapshot
 * semantics is acceptable for a test store, not for a production backend.</p>
 */
public final class MapCipherStore implements CipherStore {

    /** The single shared timestamp reported for every entry. */
    private static final FileTime EPOCH = FileTime.fromMillis(0L);

    /** Regular file contents, keyed by ciphertext name. */
    private final Map<String, byte[]> files = new ConcurrentHashMap<>();

    /** Symlink targets, keyed by ciphertext name. */
    private final Map<String, String> symlinks = new ConcurrentHashMap<>();

    /** Directory markers, including the empty root. */
    private final Set<String> dirs = ConcurrentHashMap.newKeySet();

    /** Creates an empty store. */
    public MapCipherStore() {
        dirs.add("");
    }

    @Override
    public String root() {
        return "";
    }

    @Override
    public synchronized byte[] readSmall(String name, int maxBytes) throws IOException {
        Objects.requireNonNull(name, "name");
        byte[] data = files.get(name);
        if (data == null) {
            throw new NoSuchFileException(name);
        }
        if (data.length > maxBytes) {
            throw new IOException("file too large (limit " + maxBytes + " bytes): " + name);
        }
        return data.clone();
    }

    @Override
    public synchronized void writeSmall(String name, byte[] data, boolean overwrite)
            throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        if (!overwrite && exists(name)) {
            throw new FileAlreadyExistsException(name);
        }
        ensureParent(name);
        files.put(name, data.clone());
    }

    @Override
    public synchronized CipherNode stat(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        if (dirs.contains(name)) {
            return node(name, CipherNode.Kind.DIRECTORY, 0);
        }
        String target = symlinks.get(name);
        if (target != null) {
            return node(name, CipherNode.Kind.SYMLINK,
                    target.getBytes(StandardCharsets.UTF_8).length);
        }
        byte[] data = files.get(name);
        if (data != null) {
            return node(name, CipherNode.Kind.FILE, data.length);
        }
        throw new NoSuchFileException(name);
    }

    @Override
    public synchronized List<CipherNode> list(String dir) throws IOException {
        Objects.requireNonNull(dir, "dir");
        if (!dirs.contains(dir)) {
            throw new NoSuchFileException(dir);
        }
        List<CipherNode> out = new ArrayList<>();
        for (String child : children(dir)) {
            out.add(stat(join(dir, child)));
        }
        return out;
    }

    @Override
    public synchronized void createFile(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        if (exists(name)) {
            throw new FileAlreadyExistsException(name);
        }
        ensureParent(name);
        files.put(name, new byte[0]);
    }

    @Override
    public synchronized void mkdir(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        if (exists(name)) {
            throw new FileAlreadyExistsException(name);
        }
        ensureParent(name);
        dirs.add(name);
    }

    @Override
    public synchronized void delete(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        if (dirs.contains(name)) {
            if (!children(name).isEmpty()) {
                throw new DirectoryNotEmptyException(name);
            }
            dirs.remove(name);
            return;
        }
        if (symlinks.remove(name) != null) {
            return;
        }
        if (files.remove(name) != null) {
            return;
        }
        throw new NoSuchFileException(name);
    }

    @Override
    public synchronized void rename(String from, String to, boolean replaceExisting)
            throws IOException {
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        if (!exists(from)) {
            throw new NoSuchFileException(from);
        }
        ensureParent(to);
        if (exists(to)) {
            if (!replaceExisting) {
                throw new FileAlreadyExistsException(to);
            }
            delete(to);
        }
        if (dirs.contains(from)) {
            dirs.remove(from);
            dirs.add(to);
            movePrefixed(files, from, to);
            movePrefixed(symlinks, from, to);
            movePrefixedDirs(from, to);
        } else if (symlinks.containsKey(from)) {
            symlinks.put(to, symlinks.remove(from));
        } else if (files.containsKey(from)) {
            files.put(to, files.remove(from));
        } else {
            throw new NoSuchFileException(from);
        }
    }

    @Override
    public synchronized void createSymlink(String name, String target) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(target, "target");
        if (exists(name)) {
            throw new FileAlreadyExistsException(name);
        }
        ensureParent(name);
        symlinks.put(name, target);
    }

    @Override
    public synchronized String readSymlink(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        String target = symlinks.get(name);
        if (target == null) {
            throw new NoSuchFileException(name);
        }
        return target;
    }

    @Override
    public synchronized void setTimes(String name, @Nullable FileTime lastModifiedTime,
                                      @Nullable FileTime lastAccessTime,
                                      @Nullable FileTime creationTime) throws IOException {
        Objects.requireNonNull(name, "name");
        if (!exists(name)) {
            throw new NoSuchFileException(name);
        }
        // Timestamps are not persisted in memory.
    }

    @Override
    public synchronized CipherChannel open(String name, boolean writable) throws IOException {
        Objects.requireNonNull(name, "name");
        if (!files.containsKey(name)) {
            throw new NoSuchFileException(name);
        }
        return new MemoryChannel(name, writable);
    }

    @Override
    public @Nullable PosixFileAttributes posixAttributes(String name) {
        Objects.requireNonNull(name, "name");
        return null;
    }

    @Override
    public void setPosixPermissions(String name, Set<PosixFilePermission> permissions) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(permissions, "permissions");
        throw new UnsupportedOperationException("POSIX permissions are not supported by this store");
    }

    @Override
    public void setPosixOwner(String name, UserPrincipal owner) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(owner, "owner");
        throw new UnsupportedOperationException("POSIX owner is not supported by this store");
    }

    @Override
    public void setPosixGroup(String name, GroupPrincipal group) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(group, "group");
        throw new UnsupportedOperationException("POSIX group is not supported by this store");
    }

    @Override
    public void close() {
        // No resources to release.
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private boolean exists(String name) {
        return dirs.contains(name) || symlinks.containsKey(name) || files.containsKey(name);
    }

    /**
     * Verifies that the parent directory of {@code name} exists, throwing
     * {@link NoSuchFileException} otherwise. This mirrors a real filesystem,
     * where entries can only be created below an existing directory.
     *
     * @param name the entry name whose parent to verify
     * @throws NoSuchFileException if the parent directory does not exist
     */
    private void ensureParent(String name) throws NoSuchFileException {
        if (!dirs.contains(parentOf(name))) {
            throw new NoSuchFileException(name);
        }
    }

    /**
     * Returns the direct child names of a directory, sorted.
     *
     * @param dir the directory name
     * @return the child names
     */
    private Set<String> children(String dir) {
        Set<String> out = new TreeSet<>();
        for (String f : files.keySet()) {
            if (parentOf(f).equals(dir)) {
                out.add(baseOf(f));
            }
        }
        for (String s : symlinks.keySet()) {
            if (parentOf(s).equals(dir)) {
                out.add(baseOf(s));
            }
        }
        for (String d : dirs) {
            if (!d.isEmpty() && parentOf(d).equals(dir)) {
                out.add(baseOf(d));
            }
        }
        return out;
    }

    private static String parentOf(String name) {
        int i = name.lastIndexOf('/');
        return i < 0 ? "" : name.substring(0, i);
    }

    private static String baseOf(String name) {
        int i = name.lastIndexOf('/');
        return i < 0 ? name : name.substring(i + 1);
    }

    private static String join(String parent, String child) {
        return parent.isEmpty() ? child : parent + "/" + child;
    }

    private static CipherNode node(String name, CipherNode.Kind kind, long size) {
        return new MemoryNode(baseOf(name), kind, size);
    }

    /**
     * Moves every entry whose name starts with {@code from + "/"} to the
     * equivalent name under {@code to}.
     *
     * @param <V>  the value type
     * @param map  the map to rewrite
     * @param from the source prefix
     * @param to   the target prefix
     */
    private static <V> void movePrefixed(Map<String, V> map, String from, String to) {
        String prefix = from + "/";
        List<String> keys = new ArrayList<>();
        for (String k : map.keySet()) {
            if (k.startsWith(prefix)) {
                keys.add(k);
            }
        }
        for (String k : keys) {
            map.put(to + k.substring(from.length()), map.remove(k));
        }
    }

    /**
     * Moves every subdirectory marker under {@code from} to the equivalent name
     * under {@code to}.
     *
     * @param from the source prefix
     * @param to   the target prefix
     */
    private void movePrefixedDirs(String from, String to) {
        String prefix = from + "/";
        List<String> keys = new ArrayList<>();
        for (String d : dirs) {
            if (d.startsWith(prefix)) {
                keys.add(d);
            }
        }
        for (String d : keys) {
            dirs.remove(d);
            dirs.add(to + d.substring(from.length()));
        }
    }

    /**
     * An immutable {@link CipherNode} with a fixed epoch timestamp and no file key.
     */
    private static final class MemoryNode implements CipherNode {

        private final String name;
        private final Kind kind;
        private final long size;

        MemoryNode(String name, Kind kind, long size) {
            this.name = name;
            this.kind = kind;
            this.size = size;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public Kind kind() {
            return kind;
        }

        @Override
        public long size() {
            return size;
        }

        @Override
        public FileTime lastModifiedTime() {
            return EPOCH;
        }

        @Override
        public FileTime lastAccessTime() {
            return EPOCH;
        }

        @Override
        public FileTime creationTime() {
            return EPOCH;
        }

        @Override
        public @Nullable Object fileKey() {
            return null;
        }
    }

    /**
     * A {@link CipherChannel} over an in-memory byte array. Writable
     * channels persist their contents back to the store on {@link #close()}.
     */
    private final class MemoryChannel implements CipherChannel {

        private final String name;
        private final boolean writable;
        private byte[] data;
        private long position;
        private boolean open = true;

        MemoryChannel(String name, boolean writable) {
            this.name = name;
            this.writable = writable;
            byte[] existing = files.get(name);
            this.data = existing == null ? new byte[0] : Arrays.copyOf(existing, existing.length);
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            ensureOpen();
            long remaining = data.length - position;
            if (remaining <= 0) {
                return -1;
            }
            int n = (int) Math.min(dst.remaining(), remaining);
            dst.put(data, (int) position, n);
            position += n;
            return n;
        }

        @Override
        public int write(ByteBuffer src) throws IOException {
            ensureOpen();
            if (!writable) {
                throw new NonWritableChannelException();
            }
            int n = src.remaining();
            ensureCapacity(position + n);
            src.get(data, (int) position, n);
            position += n;
            return n;
        }

        @Override
        public long position() throws IOException {
            ensureOpen();
            return position;
        }

        @Override
        public CipherChannel position(long newPosition) throws IOException {
            ensureOpen();
            if (newPosition < 0) {
                throw new IllegalArgumentException("negative position");
            }
            this.position = newPosition;
            return this;
        }

        @Override
        public long size() throws IOException {
            ensureOpen();
            return data.length;
        }

        @Override
        public CipherChannel truncate(long size) throws IOException {
            ensureOpen();
            if (!writable) {
                throw new NonWritableChannelException();
            }
            if (size < 0) {
                throw new IllegalArgumentException("negative size");
            }
            data = Arrays.copyOf(data, (int) size);
            return this;
        }

        @Override
        public boolean isOpen() {
            return open;
        }

        @Override
        public void force(boolean metaData) {
            // In-memory storage has no force primitive.
        }

        @Override
        public void close() throws IOException {
            if (open) {
                if (writable) {
                    files.put(name, data.clone());
                }
                open = false;
            }
        }

        private void ensureOpen() throws IOException {
            if (!open) {
                throw new java.nio.channels.ClosedChannelException();
            }
        }

        private void ensureCapacity(long capacity) {
            if (capacity > data.length) {
                data = Arrays.copyOf(data, (int) capacity);
            }
        }
    }
}
