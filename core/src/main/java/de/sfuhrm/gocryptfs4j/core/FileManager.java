package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;

/**
 * Performs plaintext file operations (read, write, attributes, create, delete,
 * rename) and symlink operations on top of the ciphertext store.
 *
 * <p>Every operation takes a plaintext path, resolves it to a ciphertext path
 * via the {@link PathResolver}, and performs the underlying store operation
 * plus any encryption and long-name bookkeeping. Symlink targets are encrypted
 * with the content cipher and base64url-encoded, as in gocryptfs.</p>
 */
final class FileManager {

    /** The ciphertext-side store. */
    private final CipherStore store;

    /** The content-encryption helper. */
    private final ContentEnc contentEnc;

    /** The name-transform helper. */
    private final NameTransform nameTransform;

    /** Whether file names are stored unencrypted. */
    private final boolean plaintextNames;

    /** The name manager. */
    private final NameManager nameManager;

    /** The directory manager. */
    private final DirectoryManager directoryManager;

    /** The path resolver. */
    private final PathResolver pathResolver;

    /** The number of stripes used to serialize whole-file operations. */
    private static final int FILE_LOCK_STRIPES = 64;

    /**
     * Striped locks serializing whole-file operations so that two handles to
     * the same cipher file cannot interleave header creation or size bookkeeping
     * and corrupt each other. A fixed stripe table bounds the memory used for
     * locks no matter how many different paths are ever opened.
     */
    private final Object[] fileLocks = createFileLocks();

    /**
     * Per-cipher-path shared {@link CipherFile} entries, so that concurrently
     * open channels and streams on the same file share a single backing
     * {@link CipherFile} (with its single file-id cache) instead of each
     * holding stale state that could overwrite another handle's data. An entry
     * is removed again as soon as its last handle is released, so walking many
     * files does not accumulate idle entries.
     */
    private final Map<String, SharedCipherFile.Entry> sharedFiles = new ConcurrentHashMap<>();

    /**
     * Guards channel I/O against the owning filesystem closing. Every entry
     * created here shares this guard so a close can exclude all channels at
     * once while it flushes pending writes and then wipes the keys.
     */
    private final ChannelGuard channelGuard = new ChannelGuard();

    /** When buffered writes of new handles are flushed to storage. */
    private volatile SyncPolicy syncPolicy = SyncPolicy.ON_CLOSE;

    /**
     * Creates a file manager.
     *
     * @param store            the ciphertext-side store
     * @param contentEnc       the content-encryption helper
     * @param nameTransform    the name-transform helper
     * @param plaintextNames   whether file names are stored unencrypted
     * @param nameManager      the name manager
     * @param directoryManager the directory manager
     * @param pathResolver     the path resolver
     * @throws NullPointerException if a required argument is {@code null}
     */
    FileManager(CipherStore store, ContentEnc contentEnc, NameTransform nameTransform,
                boolean plaintextNames, NameManager nameManager,
                DirectoryManager directoryManager, PathResolver pathResolver) {
        this.store = Objects.requireNonNull(store, "store");
        this.contentEnc = Objects.requireNonNull(contentEnc, "contentEnc");
        this.nameTransform = Objects.requireNonNull(nameTransform, "nameTransform");
        this.plaintextNames = plaintextNames;
        this.nameManager = Objects.requireNonNull(nameManager, "nameManager");
        this.directoryManager = Objects.requireNonNull(directoryManager, "directoryManager");
        this.pathResolver = Objects.requireNonNull(pathResolver, "pathResolver");
    }

    /**
     * Returns when buffered writes of new handles are flushed to storage.
     *
     * @return the sync policy
     */
    SyncPolicy syncPolicy() {
        return syncPolicy;
    }

    /**
     * Sets when buffered writes of new handles are flushed to storage.
     *
     * @param syncPolicy the sync policy
     */
    void setSyncPolicy(SyncPolicy syncPolicy) {
        this.syncPolicy = SyncPolicy.orDefault(syncPolicy);
    }

    // ------------------------------------------------------------------
    // Attributes
    // ------------------------------------------------------------------

    /**
     * Returns the plaintext attributes of a path (file, directory or symlink).
     *
     * @param plainPath the plaintext path
     * @return the directory entry
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    DirEntry stat(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        return statResolved(r);
    }

    /**
     * Reads the attributes of an already-resolved path.
     *
     * @param r the resolved path
     * @return the directory entry
     * @throws IOException on filesystem errors
     */
    private DirEntry statResolved(PathResolver.Resolved r) throws IOException {
        CipherNode node = store.stat(r.cipherPath);
        DirEntry.Kind kind;
        long size;
        if (node.isDirectory()) {
            kind = DirEntry.Kind.DIRECTORY;
            size = 0;
        } else if (node.isSymbolicLink()) {
            kind = DirEntry.Kind.SYMLINK;
            size = readSymlink(r.cipherPath).getBytes(StandardCharsets.UTF_8).length;
        } else if (node.isRegularFile()) {
            kind = DirEntry.Kind.FILE;
            size = plainSizeIncludingWriteBack(r.cipherPath, node.size());
        } else {
            kind = DirEntry.Kind.OTHER;
            size = node.size();
        }
        String plainName = r.plainName.isEmpty() ? "/" : r.plainName;
        return new DirEntry(plainName, r.cipherName, store.posixAttributes(r.cipherPath), kind, size,
                node.lastModifiedTime(), node.lastAccessTime(), node.creationTime(),
                node.fileKey());
    }

    // ------------------------------------------------------------------
    // Content access
    // ------------------------------------------------------------------

    /**
     * Opens a plaintext file for random access.
     *
     * @param plainFile the plaintext file path
     * @param writable  whether to open for writing
     * @return the opened cipher file handle
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    SharedCipherFile openCipherFile(String plainFile, boolean writable) throws IOException {
        return openCipherFile(plainFile, writable, syncPolicy);
    }

    /**
     * Opens a plaintext file for random access with an explicit sync policy.
     *
     * @param plainFile  the plaintext file path
     * @param writable   whether to open for writing
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened cipher file handle
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} or {@code syncPolicy} is {@code null}
     */
    SharedCipherFile openCipherFile(String plainFile, boolean writable, SyncPolicy syncPolicy)
            throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        return openCipherFileByName(r.cipherPath, writable, syncPolicy);
    }

    /**
     * Opens a cipher-side file for random access, sharing one backing
     * {@link CipherFile} (with reference counting) across all concurrently open
     * handles on the same ciphertext path.
     *
     * @param cipherFile the ciphertext file name
     * @param writable   whether to open for writing
     * @return the opened cipher file handle
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherFile} is {@code null}
     */
    SharedCipherFile openCipherFileByName(String cipherFile, boolean writable) throws IOException {
        return openCipherFileByName(cipherFile, writable, syncPolicy);
    }

    /**
     * Opens a cipher-side file for random access with an explicit sync policy,
     * sharing one backing {@link CipherFile} (with reference counting) across
     * all concurrently open handles on the same ciphertext path.
     *
     * @param cipherFile the ciphertext file name
     * @param writable   whether to open for writing
     * @param syncPolicy when buffered writes are flushed to storage on this handle
     * @return the opened cipher file handle
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherFile} or {@code syncPolicy} is {@code null}
     */
    SharedCipherFile openCipherFileByName(String cipherFile, boolean writable,
                                          SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(cipherFile, "cipherFile");
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        IOException[] ioFailure = new IOException[1];
        RuntimeException[] runtimeFailure = new RuntimeException[1];
        SharedCipherFile.Entry[] opened = new SharedCipherFile.Entry[1];
        sharedFiles.compute(cipherFile, (key, existing) -> {
            SharedCipherFile.Entry entry = existing;
            if (entry == null) {
                entry = new SharedCipherFile.Entry();
                entry.guard = channelGuard;
                entry.releaseAction = this::pruneSharedFile;
            }
            synchronized (entry.lock) {
                entry.key = cipherFile;
                try {
                    if (entry.file == null) {
                        entry.file = CipherFile.open(store.open(cipherFile, writable),
                                contentEnc, writable);
                        entry.failure = null;
                        entry.writable = writable;
                    } else if (writable && !entry.writable) {
                        // A read-only shared file is already open (other
                        // read-only handles hold it). Upgrade to a writable
                        // channel; the old one never buffered a write, so it
                        // can be retired safely. Keep it open until the entry
                        // is fully released: a reader may already have
                        // captured it and would otherwise see a closed channel.
                        CipherFile upgraded = CipherFile.open(store.open(cipherFile, true),
                                contentEnc, true);
                        CipherFile old = entry.file;
                        entry.file = upgraded;
                        entry.writable = true;
                        if (old != null) {
                            entry.retired.add(old);
                        }
                    }
                    entry.refs++;
                    opened[0] = entry;
                    return entry;
                } catch (IOException e) {
                    ioFailure[0] = e;
                    // Do not retain an entry that a failed open created.
                    return entry.refs == 0 ? null : entry;
                } catch (RuntimeException e) {
                    runtimeFailure[0] = e;
                    return entry.refs == 0 ? null : entry;
                }
            }
        });
        if (runtimeFailure[0] != null) {
            throw runtimeFailure[0];
        }
        if (ioFailure[0] != null) {
            throw ioFailure[0];
        }
        return new SharedCipherFile(opened[0], syncPolicy);
    }

    /**
     * Opens a buffered channel at the given plaintext position. The returned
     * channel owns the opened handle, so the caller closes only the channel.
     *
     * @param cipherFile the ciphertext file name
     * @param position   the initial plaintext position
     * @param writable   whether the channel permits writes
     * @return the buffered channel
     * @throws IOException on filesystem errors
     */
    private SeekableByteChannel openChannel(String cipherFile, long position, boolean writable)
            throws IOException {
        return openChannel(cipherFile, position, writable, syncPolicy);
    }

    /**
     * Opens a buffered channel at the given plaintext position with an explicit
     * sync policy.
     *
     * @param cipherFile the ciphertext file name
     * @param position   the initial plaintext position
     * @param writable   whether the channel permits writes
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the buffered channel
     * @throws IOException on filesystem errors
     */
    private SeekableByteChannel openChannel(String cipherFile, long position, boolean writable,
                                             SyncPolicy syncPolicy) throws IOException {
        try (SharedCipherFile cf = openCipherFileByName(cipherFile, writable, syncPolicy)) {
            return cf.newChannel(position, writable, syncPolicy);
        }
    }

    /**
     * Creates the fixed table of locks used to serialize whole-file operations.
     *
     * @return the lock stripe table
     */
    private static Object[] createFileLocks() {
        Object[] locks = new Object[FILE_LOCK_STRIPES];
        for (int i = 0; i < locks.length; i++) {
            locks[i] = new Object();
        }
        return locks;
    }

    /**
     * Returns the striped monitor used to serialize whole-file operations on a
     * ciphertext file. Different files may share a stripe, which only reduces
     * concurrency; operations on the same file always use the same stripe.
     *
     * @param cipherFile the ciphertext file name
     * @return the lock stripe for the file
     */
    private Object fileLock(String cipherFile) {
        return fileLocks[Math.floorMod(cipherFile.hashCode(), fileLocks.length)];
    }

    /**
     * Drops the shared {@link CipherFile} entry for a ciphertext file that no
     * longer exists. Handles already open keep their reference to the removed
     * entry and so continue to work on the unlinked file, as POSIX dictates;
     * a later open creates a fresh entry.
     *
     * @param cipherFile the ciphertext file name
     */
    private void releaseSharedFile(String cipherFile) {
        sharedFiles.remove(cipherFile);
    }

    /**
     * Removes a shared entry after its last handle has been released, unless a
     * concurrent open already acquired it again. The entry remembers its
     * current key because a rename may move it while handles are open.
     *
     * @param entry the entry to prune
     */
    private void pruneSharedFile(SharedCipherFile.Entry entry) {
        for (;;) {
            String key = entry.key;
            if (key == null) {
                return;
            }
            boolean[] removed = new boolean[1];
            sharedFiles.compute(key, (k, current) -> {
                if (current != entry) {
                    return current;
                }
                synchronized (entry.lock) {
                    if (entry.refs != 0) {
                        return current;
                    }
                    entry.key = null;
                    removed[0] = true;
                    return null;
                }
            });
            if (removed[0] || Objects.equals(key, entry.key)) {
                return;
            }
        }
    }

    /**
     * Moves the shared {@link CipherFile} entry for a ciphertext file from one
     * path to another, so a rename keeps the shared backing file attached to the
     * file it serves. A directory rename also relocates the entries of every
     * file below it. A stale entry at the target (from a replaced entry) is
     * dropped; handles already open keep their reference to the old entry.
     *
     * @param from the source ciphertext path
     * @param to   the target ciphertext path
     */
    private void moveSharedFile(String from, String to) {
        moveSharedFileEntry(from, to);
        String prefix = from + "/";
        List<String> keys = new ArrayList<>();
        for (String key : sharedFiles.keySet()) {
            if (key.startsWith(prefix)) {
                keys.add(key);
            }
        }
        for (String key : keys) {
            moveSharedFileEntry(key, to + key.substring(from.length()));
        }
    }

    /**
     * Moves a single shared entry, dropping it instead when it has no live
     * handles any more.
     *
     * @param from the source ciphertext path
     * @param to   the target ciphertext path
     */
    private void moveSharedFileEntry(String from, String to) {
        SharedCipherFile.Entry[] moved = new SharedCipherFile.Entry[1];
        sharedFiles.compute(from, (key, entry) -> {
            if (entry == null) {
                return null;
            }
            synchronized (entry.lock) {
                if (entry.refs == 0) {
                    entry.key = null;
                    return null;
                }
                entry.key = to;
                moved[0] = entry;
                return null;
            }
        });
        SharedCipherFile.Entry entry = moved[0];
        if (entry == null) {
            sharedFiles.remove(to);
            return;
        }
        sharedFiles.compute(to, (key, existing) -> {
            synchronized (entry.lock) {
                if (entry.refs == 0) {
                    entry.key = null;
                    return null;
                }
                return entry;
            }
        });
    }

    /**
     * Acquires exclusive access to every channel operation and rejects any
     * operation that starts afterwards. The caller must keep the returned lock
     * until it has flushed the shared files and wiped the keys, then release
     * it.
     *
     * @return the held close lock
     */
    Lock lockChannelsForClose() {
        Lock lock = channelGuard.writeLock();
        lock.lock();
        channelGuard.markClosed();
        return lock;
    }

    /**
     * Flushes any pending buffered block of every shared cipher file. Called
     * before the content-encryption keys are wiped on close, so that buffered
     * plaintext is still encrypted and written while the keys are valid.
     *
     * @throws IOException on filesystem or encryption errors
     */
    void flushSharedFiles() throws IOException {
        IOException failure = null;
        for (SharedCipherFile.Entry entry : sharedFiles.values()) {
            try {
                SharedCipherFile.flushEntry(entry);
            } catch (IOException e) {
                if (failure == null) {
                    failure = e;
                } else {
                    failure.addSuppressed(e);
                }
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    /**
     * Returns the plaintext size of a cipher file, accounting for any unflushed
     * buffered block of an open channel on that file. The store's ciphertext
     * size alone misses a block that has been buffered by an open channel but
     * not yet written through.
     *
     * @param cipherFile the ciphertext file path
     * @param cipherSize the ciphertext size reported by the store
     * @return the plaintext size including buffered channel data
     * @throws IOException on filesystem errors
     */
    long plainSizeIncludingWriteBack(String cipherFile, long cipherSize) throws IOException {
        long size = contentEnc.cipherSizeToPlainSize(cipherSize);
        SharedCipherFile.Entry entry = sharedFiles.get(cipherFile);
        if (entry != null) {
            size = Math.max(size, SharedCipherFile.effectiveSize(entry));
        }
        return size;
    }

    /**
     * Returns the plaintext size of a file.
     *
     * @param plainFile the plaintext file path
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    long size(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        synchronized (fileLock(r.cipherPath)) {
            try (SharedCipherFile cf = openCipherFileByName(r.cipherPath, false)) {
                return cf.effectiveSize();
            }
        }
    }

    /**
     * Reads the entire plaintext content of a file.
     *
     * @param plainFile the plaintext file path
     * @return the plaintext content
     * @throws IOException on filesystem or decryption errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    byte[] readAll(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        synchronized (fileLock(r.cipherPath)) {
            try (SharedCipherFile cf = openCipherFileByName(r.cipherPath, false)) {
                // Another handle may hold unflushed buffered blocks; flush them
                // so this read sees the same content, then read back.
                cf.flushChannels();
                try (SeekableByteChannel ch = cf.newChannel(0, false)) {
                    long size = ch.size();
                    if (size > Integer.MAX_VALUE) {
                        throw new IOException("file too large to read into memory: " + size);
                    }
                    byte[] out = new byte[(int) size];
                    int pos = 0;
                    while (pos < size) {
                        int n = ch.read(ByteBuffer.wrap(out, pos, (int) (size - pos)));
                        if (n < 0) {
                            break;
                        }
                        pos += n;
                    }
                    return Arrays.copyOf(out, pos);
                }
            }
        }
    }

    /**
     * Opens a streaming, decrypting input stream over a plaintext file path.
     *
     * @param plainFile the plaintext file path
     * @return the decrypting input stream
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    InputStream openRead(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        SeekableByteChannel ch = openChannel(r.cipherPath, 0, false);
        try {
            return new CipherInputStream(ch);
        } catch (RuntimeException e) {
            ch.close();
            throw e;
        }
    }

    /**
     * Opens a streaming, encrypting output stream over a plaintext file path.
     *
     * <p>Writing starts at the beginning of the file, overwriting any existing
     * content. Closing the stream closes the underlying file and flushes the
     * encrypted data.</p>
     *
     * @param plainFile the plaintext file path
     * @return the encrypting output stream
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    OutputStream openWrite(String plainFile) throws IOException {
        return openWrite(plainFile, syncPolicy);
    }

    /**
     * Opens a streaming, encrypting output stream with an explicit sync policy.
     *
     * @param plainFile  the plaintext file path
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the encrypting output stream
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} or {@code syncPolicy} is {@code null}
     */
    OutputStream openWrite(String plainFile, SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        try (SharedCipherFile cf = openCipherFileByName(r.cipherPath, true, syncPolicy)) {
            cf.truncate(0);
            return Channels.newOutputStream(cf.newChannel(0, true, syncPolicy));
        }
    }

    /**
     * Writes {@code data} at plaintext {@code offset} of an existing file.
     *
     * @param plainFile the plaintext file path
     * @param offset    the plaintext offset to write at
     * @param data      the data to write
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plainFile} or {@code data} is {@code null}
     * @throws IllegalArgumentException if {@code offset} is negative
     */
    void write(String plainFile, long offset, byte[] data) throws IOException {
        write(plainFile, offset, data, syncPolicy);
    }

    /**
     * Writes {@code data} at plaintext {@code offset} with an explicit sync
     * policy.
     *
     * @param plainFile  the plaintext file path
     * @param offset     the plaintext offset to write at
     * @param data       the data to write
     * @param syncPolicy when buffered writes are flushed to storage
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plainFile}, {@code data} or {@code syncPolicy} is {@code null}
     * @throws IllegalArgumentException if {@code offset} is negative
     */
    void write(String plainFile, long offset, byte[] data, SyncPolicy syncPolicy)
            throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        if (offset < 0) {
            throw new IllegalArgumentException("negative offset: " + offset);
        }
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        synchronized (fileLock(r.cipherPath)) {
            try (SeekableByteChannel ch = openChannel(r.cipherPath, offset, true, syncPolicy)) {
                ByteBuffer buf = ByteBuffer.wrap(data);
                while (buf.hasRemaining()) {
                    int n = ch.write(buf);
                    if (n <= 0) {
                        throw new IOException("no progress writing to " + plainFile);
                    }
                }
            }
        }
    }

    /**
     * Truncates a plaintext file to {@code newSize} bytes.
     *
     * @param plainFile the plaintext file path
     * @param newSize   the new plaintext size in bytes
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     * @throws IllegalArgumentException if {@code newSize} is negative
     */
    void truncate(String plainFile, long newSize) throws IOException {
        truncate(plainFile, newSize, syncPolicy);
    }

    /**
     * Truncates a plaintext file with an explicit sync policy.
     *
     * @param plainFile  the plaintext file path
     * @param newSize    the new plaintext size in bytes
     * @param syncPolicy when buffered writes are flushed to storage
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plainFile} or {@code syncPolicy} is {@code null}
     * @throws IllegalArgumentException if {@code newSize} is negative
     */
    void truncate(String plainFile, long newSize, SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        if (newSize < 0) {
            throw new IllegalArgumentException("negative size: " + newSize);
        }
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        synchronized (fileLock(r.cipherPath)) {
            try (SharedCipherFile cf = openCipherFileByName(r.cipherPath, true, syncPolicy)) {
                cf.truncate(newSize);
            }
        }
    }

    // ------------------------------------------------------------------
    // Metadata
    // ------------------------------------------------------------------

    /**
     * Sets the last-modified, last-access and creation times of a path.
     *
     * @param plainPath        the plaintext path
     * @param lastModifiedTime the last-modified time
     * @param lastAccessTime   the last-access time
     * @param createTime       the creation time
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    void setTimes(String plainPath, @Nullable FileTime lastModifiedTime,
                  @Nullable FileTime lastAccessTime, @Nullable FileTime createTime)
            throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.setTimes(r.cipherPath, lastModifiedTime, lastAccessTime, createTime);
    }

    /**
     * Checks access to a plaintext path, delegating to the store. Existence (no
     * modes) is verified by resolving the path itself; stores that cannot
     * evaluate read/write/execute throw {@link UnsupportedOperationException}.
     *
     * @param plainPath the plaintext path
     * @param modes     the access modes to check, or none to check existence
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    void checkAccess(String plainPath, AccessMode... modes) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.checkAccess(r.cipherPath, modes);
    }

    /**
     * Returns the POSIX attributes of a plaintext path's backing cipher file,
     * or {@code null} if the store has no POSIX support.
     *
     * @param plainPath the plaintext path
     * @return the POSIX attributes, or {@code null}
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    @Nullable PosixFileAttributes posixAttributes(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        return store.posixAttributes(r.cipherPath);
    }

    /**
     * Sets the POSIX permissions of a plaintext path's backing cipher file.
     *
     * @param plainPath   the plaintext path
     * @param permissions the new permissions
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} or {@code permissions} is {@code null}
     */
    void setPosixPermissions(String plainPath, Set<PosixFilePermission> permissions)
            throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(permissions, "permissions");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.setPosixPermissions(r.cipherPath, permissions);
    }

    /**
     * Sets the POSIX owner of a plaintext path's backing cipher file.
     *
     * @param plainPath the plaintext path
     * @param owner     the new owner
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} or {@code owner} is {@code null}
     */
    void setPosixOwner(String plainPath, UserPrincipal owner) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(owner, "owner");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.setPosixOwner(r.cipherPath, owner);
    }

    /**
     * Sets the POSIX group of a plaintext path's backing cipher file.
     *
     * @param plainPath the plaintext path
     * @param group     the new group
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} or {@code group} is {@code null}
     */
    void setPosixGroup(String plainPath, GroupPrincipal group) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(group, "group");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.setPosixGroup(r.cipherPath, group);
    }

    // ------------------------------------------------------------------
    // Create / delete / rename
    // ------------------------------------------------------------------

    /**
     * Creates an empty file (fails if it already exists).
     *
     * @param plainFile the plaintext file path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    void createFile(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolveParent(plainFile, true);
        boolean wroteName = nameManager.prepareLongName(r);
        try {
            store.createFile(r.cipherPath);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                nameManager.removeLongName(r);
            }
            throw e;
        }
    }

    /**
     * Creates a directory (including its diriv).
     *
     * @param plainDir the plaintext directory path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    void mkdir(String plainDir) throws IOException {
        Objects.requireNonNull(plainDir, "plainDir");
        PathResolver.Resolved r = pathResolver.resolveParent(plainDir, true);
        boolean wroteName = nameManager.prepareLongName(r);
        try {
            store.mkdir(r.cipherPath);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                nameManager.removeLongName(r);
            }
            throw e;
        }
        try {
            directoryManager.writeDirIV(r.cipherPath);
        } catch (IOException | RuntimeException e) {
            try {
                deleteIfExists(store, PathResolver.join(r.cipherPath, Constants.DIR_IV_FILENAME));
                store.delete(r.cipherPath);
                nameManager.removeLongName(r);
            } catch (IOException cleanup) {
                e.addSuppressed(cleanup);
            }
            throw e;
        }
    }

    /**
     * Deletes a file, symlink or empty directory.
     *
     * @param plainPath the plaintext path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    void delete(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        if (store.stat(r.cipherPath).isDirectory()) {
            removeEmptyDir(r.cipherPath);
        } else {
            store.delete(r.cipherPath);
        }
        releaseSharedFile(r.cipherPath);
        nameManager.removeLongName(r);
        directoryManager.invalidateDirIvCache(r.cipherPath);
    }

    /**
     * Renames (moves) a file, symlink or directory within this filesystem by
     * renaming the single ciphertext entry.
     *
     * <p>No content is read or re-encrypted: file content is bound to the file
     * ID stored in its header, directory contents are bound to the directory's
     * own {@code gocryptfs.diriv}, and symlink targets are not path-bound, so
     * only the entry's encrypted name (and its long-name support file, if any)
     * changes. Directories are therefore moved together with their whole
     * subtree. An existing file or symlink target is replaced atomically. A
     * directory target is replaced only by another directory, after verifying
     * the target is empty apart from its {@code gocryptfs.diriv}; the target's
     * diriv is removed so the rename is atomic and restored if it fails.</p>
     *
     * @param plainFrom       the plaintext source path
     * @param plainTo         the plaintext target path
     * @param replaceExisting whether an existing target (a file, symlink or
     *                        empty directory) may be replaced
     * @throws NoSuchFileException if the source or the target's parent does not exist
     * @throws FileAlreadyExistsException if the target exists and {@code replaceExisting} is {@code false}
     * @throws DirectoryNotEmptyException if the target is a non-empty directory
     * @throws FileSystemException if a non-directory source would replace a directory
     * @throws IOException if the target lies inside the source or on filesystem errors
     * @throws NullPointerException if an argument is {@code null}
     */
    void rename(String plainFrom, String plainTo, boolean replaceExisting)
            throws IOException {
        Objects.requireNonNull(plainFrom, "plainFrom");
        Objects.requireNonNull(plainTo, "plainTo");
        List<String> fromComps = PathResolver.normalize(plainFrom);
        List<String> toComps = PathResolver.normalize(plainTo);
        if (fromComps.isEmpty() || toComps.isEmpty()) {
            throw new IOException("cannot rename the root directory");
        }
        PathResolver.Resolved from = pathResolver.resolveParent(plainFrom);
        CipherNode fromNode;
        try {
            fromNode = store.stat(from.cipherPath);
        } catch (NoSuchFileException e) {
            throw new NoSuchFileException(plainFrom);
        }
        if (fromComps.equals(toComps)) {
            return;
        }
        if (toComps.size() > fromComps.size()
                && toComps.subList(0, fromComps.size()).equals(fromComps)) {
            throw new IOException("cannot move " + plainFrom + " into its own subtree: " + plainTo);
        }
        PathResolver.Resolved to = pathResolver.resolveParent(plainTo, true);
        String movedDirIV = null;
        if (exists(to.cipherPath)) {
            if (!replaceExisting) {
                throw new FileAlreadyExistsException(plainTo);
            }
            if (store.stat(to.cipherPath).isDirectory()) {
                // A directory can only be replaced by another directory, and
                // only when it is empty apart from its gocryptfs.diriv. Verify
                // both before removing anything so a rejected replace leaves the
                // target intact.
                verifyEmptyDir(to.cipherPath);
                if (!fromNode.isDirectory()) {
                    throw new FileSystemException(plainFrom, plainTo,
                            "cannot replace a directory with a non-directory");
                }
                // An atomic rename cannot replace a directory that still
                // contains its gocryptfs.diriv, so move the diriv aside in the
                // parent, leaving the now-truly-empty directory in place for
                // the store to replace atomically. The diriv is moved back if
                // the rename fails.
                if (directoryManager.usesDirIV()) {
                    movedDirIV = directoryManager.moveDirIVAside(to.cipherPath);
                }
            }
            // A non-directory target is replaced atomically by the rename below.
        }
        boolean wroteName = false;
        try {
            wroteName = nameManager.prepareLongName(to);
            store.rename(from.cipherPath, to.cipherPath, replaceExisting);
        } catch (IOException | RuntimeException e) {
            // Restore the target's diriv so a failed directory replace leaves
            // the target directory intact.
            if (movedDirIV != null) {
                try {
                    directoryManager.restoreDirIV(to.cipherPath, movedDirIV);
                } catch (IOException restore) {
                    e.addSuppressed(restore);
                }
            }
            // prepareLongName may have created a long-name support file that no
            // longer has a matching entry; drop it so a failed rename leaves no
            // orphan behind.
            if (wroteName) {
                nameManager.removeLongName(to);
            }
            throw e;
        }
        if (movedDirIV != null) {
            try {
                deleteIfExists(store, movedDirIV);
            } catch (IOException cleanup) {
                // The replace succeeded; only the moved-aside diriv is left.
            }
        }
        nameManager.removeLongName(from);
        moveSharedFile(from.cipherPath, to.cipherPath);
        directoryManager.invalidateDirIvCache(from.cipherPath);
        directoryManager.invalidateDirIvCache(to.cipherPath);
    }

    // ------------------------------------------------------------------
    // Symlinks
    // ------------------------------------------------------------------

    /**
     * Reads and decrypts the target of a cipher-side symlink.
     *
     * @param cipherSymlink the ciphertext symlink name
     * @return the plaintext symlink target
     * @throws IOException on filesystem or decryption errors
     * @throws NullPointerException if {@code cipherSymlink} is {@code null}
     */
    String readSymlink(String cipherSymlink) throws IOException {
        Objects.requireNonNull(cipherSymlink, "cipherSymlink");
        return readSymlink(cipherSymlink, store, contentEnc, nameTransform, plaintextNames);
    }

    /**
     * Reads and decrypts the target of a plaintext symlink path.
     *
     * @param plainPath the plaintext symlink path
     * @return the plaintext symlink target
     * @throws IOException on filesystem or decryption errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    String readSymlinkTarget(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        return readSymlink(r.cipherPath);
    }

    /**
     * Creates a symlink pointing to {@code target}.
     *
     * @param plainPath the plaintext symlink path
     * @param target    the plaintext target
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plainPath} or {@code target} is {@code null}
     */
    void createSymlink(String plainPath, String target) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(target, "target");
        PathResolver.Resolved r = pathResolver.resolveParent(plainPath, true);
        boolean wroteName = nameManager.prepareLongName(r);
        try {
            String cTarget = encryptSymlinkTarget(target, contentEnc, nameTransform, plaintextNames);
            store.createSymlink(r.cipherPath, cTarget);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                nameManager.removeLongName(r);
            }
            throw e;
        }
    }

    /**
     * Encrypts and base64url-encodes a plaintext symlink target.
     *
     * @param target         the plaintext target
     * @param contentEnc     the content-encryption helper
     * @param nameTransform  the name-transform helper
     * @param plaintextNames whether names (and symlink targets) are unencrypted
     * @return the stored (ciphertext) symlink target
     */
    static String encryptSymlinkTarget(String target, ContentEnc contentEnc,
                                       NameTransform nameTransform, boolean plaintextNames) {
        if (plaintextNames || target.isEmpty()) {
            return target;
        }
        byte[] enc = contentEnc.encryptBlock(target.getBytes(StandardCharsets.UTF_8), 0, null);
        return nameTransform.b64Encode(enc);
    }

    /**
     * Reads and decrypts the target of a cipher-side symlink.
     *
     * @param cipherSymlink  the ciphertext symlink name
     * @param store          the ciphertext-side store
     * @param contentEnc     the content-encryption helper
     * @param nameTransform  the name-transform helper
     * @param plaintextNames whether names (and symlink targets) are unencrypted
     * @return the plaintext symlink target
     * @throws IOException on filesystem or decryption errors
     */
    static String readSymlink(String cipherSymlink, CipherStore store, ContentEnc contentEnc,
                              NameTransform nameTransform, boolean plaintextNames)
            throws IOException {
        String target = store.readSymlink(cipherSymlink);
        if (plaintextNames || target.isEmpty()) {
            return target;
        }
        byte[] cData;
        try {
            cData = nameTransform.b64Decode(target);
        } catch (IllegalArgumentException e) {
            throw new IOException("corrupt symlink target", e);
        }
        try {
            byte[] data = contentEnc.decryptBlock(cData, 0, null);
            return new String(data, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IOException("corrupt symlink target", e);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Removes an empty ciphertext directory together with its
     * {@code gocryptfs.diriv}, if one is used.
     *
     * <p>The directory is verified empty first so a rejected removal leaves it
     * intact. In per-directory-IV mode the diriv is moved aside in the parent
     * before the directory itself is removed; if that fails (for example
     * because an entry appeared concurrently, a permission error, or a remote
     * store), the diriv is moved back so the names in the directory stay
     * decryptable.</p>
     *
     * <p>In plaintext-names and deterministic-names mode there is no
     * {@code gocryptfs.diriv}, so an entry of that name is an ordinary user
     * entry: it makes the directory non-empty and is never deleted here.</p>
     *
     * @param cipherDir the ciphertext directory to remove
     * @throws DirectoryNotEmptyException if the directory is not empty
     * @throws IOException on filesystem errors
     */
    private void removeEmptyDir(String cipherDir) throws IOException {
        verifyEmptyDir(cipherDir);
        if (directoryManager.usesDirIV()) {
            removeEmptyDirWithDirIV(cipherDir);
            return;
        }
        store.delete(cipherDir);
    }

    /**
     * Verifies that {@code cipherDir} contains no entries other than its
     * {@code gocryptfs.diriv} (in per-directory-IV mode) or no entries at all
     * (otherwise).
     *
     * @param cipherDir the ciphertext directory to check
     * @throws DirectoryNotEmptyException if the directory is not empty
     * @throws IOException on filesystem errors
     */
    private void verifyEmptyDir(String cipherDir) throws IOException {
        if (directoryManager.usesDirIV()) {
            for (CipherNode entry : store.list(cipherDir)) {
                if (!entry.name().equals(Constants.DIR_IV_FILENAME)) {
                    throw new DirectoryNotEmptyException(cipherDir);
                }
            }
            return;
        }
        // No per-directory IV is used, so gocryptfs.diriv is an ordinary entry
        // and any entry makes the directory non-empty.
        if (!store.list(cipherDir).isEmpty()) {
            throw new DirectoryNotEmptyException(cipherDir);
        }
    }

    /**
     * Removes a ciphertext directory (already verified empty by
     * {@link #verifyEmptyDir(String)}) together with its {@code gocryptfs.diriv}.
     *
     * <p>The diriv is moved aside in the parent before the directory is
     * removed and moved back if the removal fails, so a concurrent external
     * writer that mints a fresh diriv is never overwritten.</p>
     *
     * @param cipherDir the ciphertext directory to remove
     * @throws IOException on filesystem errors
     */
    private void removeEmptyDirWithDirIV(String cipherDir) throws IOException {
        String aside = directoryManager.moveDirIVAside(cipherDir);
        try {
            store.delete(cipherDir);
        } catch (IOException | RuntimeException e) {
            try {
                directoryManager.restoreDirIV(cipherDir, aside);
            } catch (IOException restore) {
                e.addSuppressed(restore);
            }
            throw e;
        }
        try {
            deleteIfExists(store, aside);
        } catch (IOException cleanup) {
            // The directory is gone; only the moved-aside diriv is left.
        }
    }

    /**
     * Deletes a ciphertext entry, ignoring an already-absent entry.
     *
     * @param store the store
     * @param name  the ciphertext path to delete
     * @throws IOException on storage errors other than the entry being absent
     */
    static void deleteIfExists(CipherStore store, String name) throws IOException {
        try {
            store.delete(name);
        } catch (NoSuchFileException ignored) {
            // Already gone.
        }
    }

    /**
     * Returns whether a ciphertext entry exists.
     *
     * @param name the ciphertext path
     * @return {@code true} if the entry exists
     * @throws IOException on storage errors other than the entry being absent
     */
    private boolean exists(String name) throws IOException {
        try {
            store.stat(name);
            return true;
        } catch (NoSuchFileException e) {
            return false;
        }
    }

    /**
     * A streaming, decrypting {@link InputStream} over a buffered channel.
     *
     * <p>The underlying {@link BlockBufferedChannel} buffers one plaintext block,
     * so single-byte reads stay efficient. Closing the stream closes the
     * channel, which flushes and wipes its plaintext buffer and releases the
     * shared file.</p>
     */
    private static final class CipherInputStream extends InputStream {

        /** The buffered channel being read. */
        private final SeekableByteChannel ch;

        /**
         * Creates a stream over the given channel.
         *
         * @param ch the channel to read from
         */
        CipherInputStream(SeekableByteChannel ch) {
            this.ch = ch;
        }

        /**
         * Reads a single plaintext byte.
         *
         * @return the byte, or {@code -1} at the end of the stream
         * @throws IOException on filesystem errors
         */
        @Override
        public int read() throws IOException {
            ByteBuffer one = ByteBuffer.allocate(1);
            int n = ch.read(one);
            return n < 0 ? -1 : (one.get(0) & 0xFF);
        }

        /**
         * Reads plaintext bytes into a range of an array.
         *
         * @param b   the destination buffer
         * @param off the destination offset
         * @param len the maximum number of bytes
         * @return the number of bytes read, or {@code -1} at the end of the stream
         * @throws IOException on filesystem errors
         */
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            return ch.read(ByteBuffer.wrap(b, off, len));
        }

        /**
         * Closes the underlying channel. Calling this method more than once has
         * no effect.
         *
         * @throws IOException on filesystem errors
         */
        @Override
        public void close() throws IOException {
            ch.close();
        }
    }
}
