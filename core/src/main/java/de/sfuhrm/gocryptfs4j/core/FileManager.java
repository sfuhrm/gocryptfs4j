package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.ContentGeometry;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.function.Supplier;

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

    /** The content-encryption block geometry. */
    private final ContentGeometry contentGeometry;

    /** Mints a fresh keyed content-encryption helper per file and per transient use. */
    private final Supplier<ContentEnc> contentEncFactory;

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
     * Every entry that currently has a live backing file, including entries
     * removed from {@link #sharedFiles} by a delete or a replace. Filesystem
     * close uses this set to wipe content keys even when their path is gone.
     */
    private final Set<SharedCipherFile.Entry> openEntries = ConcurrentHashMap.newKeySet();

    /**
     * Guards channel I/O against the owning filesystem closing or moving and
     * deleting paths. Every entry created here shares this guard so a close can
     * exclude all channels at once while it flushes pending writes and then
     * wipes the keys, and a rename or delete can wait for in-flight writes.
     */
    private final ChannelGuard channelGuard = new ChannelGuard();

    /** When buffered writes of new handles are flushed to storage. */
    private volatile SyncPolicy syncPolicy = SyncPolicy.ON_CLOSE;

    /**
     * Creates a file manager.
     *
     * @param store            the ciphertext-side store
     * @param contentGeometry  the content block geometry
     * @param contentEncFactory mints a fresh content-encryption helper per file
     *                          and per transient use
     * @param nameTransform    the name-transform helper
     * @param plaintextNames   whether file names are stored unencrypted
     * @param nameManager      the name manager
     * @param directoryManager the directory manager
     * @param pathResolver     the path resolver
     * @throws NullPointerException if a required argument is {@code null}
     */
    FileManager(CipherStore store, ContentGeometry contentGeometry,
                Supplier<ContentEnc> contentEncFactory, NameTransform nameTransform,
                boolean plaintextNames, NameManager nameManager,
                DirectoryManager directoryManager, PathResolver pathResolver) {
        this.store = Objects.requireNonNull(store, "store");
        this.contentGeometry = Objects.requireNonNull(contentGeometry, "contentGeometry");
        this.contentEncFactory = Objects.requireNonNull(contentEncFactory, "contentEncFactory");
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
        CipherNode node = store.stat(r.cipherPath());
        DirEntry.Kind kind;
        long size;
        if (node.isDirectory()) {
            kind = DirEntry.Kind.DIRECTORY;
            size = 0;
        } else if (node.isSymbolicLink()) {
            kind = DirEntry.Kind.SYMLINK;
            size = readSymlink(r.cipherPath()).getBytes(StandardCharsets.UTF_8).length;
        } else if (node.isRegularFile()) {
            kind = DirEntry.Kind.FILE;
            size = plainSizeIncludingWriteBack(r.cipherPath(), node.size());
        } else {
            kind = DirEntry.Kind.OTHER;
            size = node.size();
        }
        String plainName = r.plainName().isEmpty() ? "/" : r.plainName();
        return new DirEntry(plainName, r.cipherName(), store.posixAttributes(r.cipherPath()), kind, size,
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
        return openCipherFileByName(r.cipherPath(), writable, syncPolicy);
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
     * <p>The shared entry is reserved under the registry's map lock, but the
     * store channel is opened and its content key derived only afterwards, so
     * slow I/O never runs while holding that lock.</p>
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
        SharedCipherFile.Entry entry = reserveSharedEntry(cipherFile);
        boolean opened = false;
        try {
            synchronized (entry.lock) {
                IOException failure = entry.failure;
                if (failure != null) {
                    // A previous flush failed and its dirty block may have been
                    // discarded. Never let a reopen hide that loss.
                    throw failure;
                }
                if (entry.file == null) {
                    // Opening the channel, deriving the content key and
                    // initializing the cipher all happen outside the map's bin
                    // lock, so an unrelated open is never stalled behind this
                    // store or crypto work.
                    entry.file = openBackingFile(store, cipherFile, writable,
                            contentEncFactory);
                    entry.writable = writable;
                } else if (writable && !entry.writable) {
                    // A read-only shared file is already open (other read-only
                    // handles hold it). Upgrade to a writable channel; the old
                    // one never buffered a write, so it can be retired safely.
                    // Keep it open until the entry is fully released: a reader
                    // may already have captured it and would otherwise see a
                    // closed channel.
                    CipherFile upgraded = openBackingFile(store, cipherFile, true,
                            contentEncFactory);
                    CipherFile old = entry.file;
                    entry.file = upgraded;
                    entry.writable = true;
                    if (old != null) {
                        entry.retired.add(old);
                    }
                }
                openEntries.add(entry);
            }
            SharedCipherFile handle = new SharedCipherFile(entry, syncPolicy);
            opened = true;
            return handle;
        } finally {
            if (!opened) {
                releaseReservedEntry(entry);
            }
        }
    }

    /**
     * Reserves a reference to the shared entry for a ciphertext file. The entry
     * is created or found with a plain map operation and its reference is then
     * incremented under {@code entry.lock}, never while holding the map's bin
     * lock. Holding the bin lock only for the lookup keeps a slow open (which
     * may hold {@code entry.lock} for its store I/O) from stalling unrelated
     * paths that hash to the same bin.
     *
     * <p>If a concurrent prune or rename detaches the entry between the lookup
     * and the reference increment, the reservation is retried against the
     * current mapping.</p>
     *
     * @param cipherFile the ciphertext file name
     * @return the reserved entry
     */
    private SharedCipherFile.Entry reserveSharedEntry(String cipherFile) {
        for (;;) {
            SharedCipherFile.Entry entry = sharedFiles.get(cipherFile);
            if (entry == null) {
                SharedCipherFile.Entry fresh = new SharedCipherFile.Entry();
                fresh.guard = channelGuard;
                fresh.releaseAction = this::releaseEntry;
                fresh.key = cipherFile;
                entry = sharedFiles.putIfAbsent(cipherFile, fresh);
                if (entry == null) {
                    entry = fresh;
                }
            }
            // refs is protected by entry.lock everywhere else. Taking it
            // outside the map's bin lock prevents a slow I/O in another holder
            // of this entry from blocking unrelated keys in the same bin.
            synchronized (entry.lock) {
                if (sharedFiles.get(cipherFile) != entry) {
                    // A prune or rename detached the entry after the lookup;
                    // reserve against the mapping that replaced it.
                    continue;
                }
                entry.key = cipherFile;
                entry.refs++;
                return entry;
            }
        }
    }

    /**
     * Releases the reference reserved by {@link #reserveSharedEntry} when the
     * backing file could not be opened.
     *
     * @param entry the reserved entry
     */
    private void releaseReservedEntry(SharedCipherFile.Entry entry) {
        synchronized (entry.lock) {
            entry.refs--;
        }
        releaseEntry(entry);
    }

    /**
     * Opens a backing {@link CipherFile} for {@code cipherFile}, opening the
     * store channel first and only then deriving the content key, so a failure
     * in either step does not leak the already-opened channel or an unwiped
     * derived key. Package-private for testing.
     *
     * @param store             the ciphertext-side store
     * @param cipherFile        the ciphertext file name
     * @param writable          whether to open for writing
     * @param contentEncFactory mints a fresh content-encryption helper
     * @return the opened backing file
     * @throws IOException on filesystem errors
     */
    static CipherFile openBackingFile(CipherStore store, String cipherFile, boolean writable,
                                      Supplier<ContentEnc> contentEncFactory) throws IOException {
        CipherJournal journal = new CipherJournal(store, cipherFile);
        // A journal is replayed only by a writable open, which runs under the
        // cipher root lock. A read-only open must never replay, modify, or
        // remove a journal: it fails in CipherFile.recoverJournal() instead.
        CipherChannel channel = store.open(cipherFile, writable);
        ContentEnc enc = null;
        CipherFile file = null;
        try {
            enc = contentEncFactory.get();
            file = CipherFile.open(channel, enc, writable, journal);
            file.recoverJournal();
            return file;
        } catch (IOException | RuntimeException | Error e) {
            if (file != null) {
                try {
                    file.close();
                } catch (IOException closeFailure) {
                    e.addSuppressed(closeFailure);
                }
            } else {
                if (enc != null) {
                    enc.wipe();
                }
                try {
                    channel.close();
                } catch (IOException closeFailure) {
                    e.addSuppressed(closeFailure);
                }
            }
            throw e;
        }
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
     * Drops a fully released entry from the open-file registry and prunes its
     * path entry. A failed close stays registered by path so the next open
     * reports the loss, but its backing file is already gone.
     *
     * @param entry the entry whose last handle was released
     */
    private void releaseEntry(SharedCipherFile.Entry entry) {
        synchronized (entry.lock) {
            if (entry.refs == 0) {
                openEntries.remove(entry);
            }
        }
        pruneSharedFile(entry);
    }

    /**
     * Removes a shared entry after its last handle has been released, unless a
     * concurrent open already acquired it again. The entry remembers its
     * current key because a rename may move it while handles are open.
     *
     * <p>The entry monitor is taken before the map is touched, so this never
     * waits for a slow channel I/O while holding a bin lock. A rename moves the
     * entry under the same monitor, so the key stays stable while it is held
     * and no retry loop is needed.</p>
     *
     * @param entry the entry to prune
     */
    private void pruneSharedFile(SharedCipherFile.Entry entry) {
        synchronized (entry.lock) {
            if (entry.refs != 0 || entry.failure != null) {
                // A concurrent failed close may have marked the entry after the
                // release that scheduled this prune. Keep it so the failure
                // stays visible to the next open.
                return;
            }
            String key = entry.key;
            if (key == null) {
                return;
            }
            if (sharedFiles.remove(key, entry)) {
                entry.key = null;
            }
            // If the key now maps to another entry (or was already removed by
            // a delete or replace), this entry is already detached. Leave it
            // alone; handles that still hold it release without a backing file.
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
     * handles any more. The entry monitor is taken outside the map's bin lock
     * and then guards the key update and the map move, so a rename never waits
     * for a slow open while holding a bin lock.
     *
     * @param from the source ciphertext path
     * @param to   the target ciphertext path
     */
    private void moveSharedFileEntry(String from, String to) {
        for (;;) {
            SharedCipherFile.Entry entry = sharedFiles.get(from);
            if (entry == null) {
                // Nothing live to move. Drop any entry at the target so later
                // opens see the renamed file; open handles keep their own entry.
                sharedFiles.remove(to);
                return;
            }
            synchronized (entry.lock) {
                if (sharedFiles.get(from) != entry) {
                    // A concurrent prune, move or replace changed the mapping
                    // between the lookup and taking the entry monitor.
                    continue;
                }
                if (entry.refs == 0 && entry.failure == null) {
                    if (!sharedFiles.remove(from, entry)) {
                        continue;
                    }
                    entry.key = null;
                    sharedFiles.remove(to);
                    return;
                }
                if (!sharedFiles.remove(from, entry)) {
                    continue;
                }
                entry.key = to;
                sharedFiles.put(to, entry);
                return;
            }
        }
    }

    /**
     * Prepares the journals of every open file under a renamed ciphertext path
     * to move to the new path. The caller must hold the channel write lock and
     * call {@link #commitJournalMoves(List)} after the store rename succeeds, or
     * {@link #rollbackJournalMoves(List, Throwable)} if it fails.
     *
     * @param from the source ciphertext path
     * @param to   the target ciphertext path
     * @return the pending journal moves
     * @throws IOException on filesystem errors
     */
    private List<JournalMove> prepareJournalMoves(String from, String to) throws IOException {
        List<JournalMove> moves = new ArrayList<>();
        boolean exactCovered = false;
        String prefix = from + "/";
        List<String> keys = new ArrayList<>();
        for (String key : sharedFiles.keySet()) {
            if (key.equals(from) || key.startsWith(prefix)) {
                keys.add(key);
            }
        }
        try {
            for (String key : keys) {
                SharedCipherFile.Entry entry = sharedFiles.get(key);
                if (entry == null) {
                    continue;
                }
                CipherFile file;
                synchronized (entry.lock) {
                    file = entry.file;
                    if (file != null) {
                        CipherJournal.Move move =
                                file.beginJournalMove(renamedCipherPath(from, to, key));
                        if (move != null) {
                            moves.add(JournalMove.forFile(file, move));
                        }
                        if (key.equals(from)) {
                            exactCovered = true;
                        }
                    }
                }
                if (file == null) {
                    // A failed close keeps the entry registered without a
                    // backing file; its journal may still be pending.
                    CipherJournal journal = new CipherJournal(store, key);
                    CipherJournal.Move move = journal.beginMove(renamedCipherPath(from, to, key));
                    if (move != null) {
                        moves.add(JournalMove.forJournal(journal, move));
                    }
                    if (key.equals(from)) {
                        exactCovered = true;
                    }
                }
            }
            if (!exactCovered) {
                // No open backing file for the source path, but a crashed or
                // failed write may still have left a journal there.
                CipherJournal journal = new CipherJournal(store, from);
                CipherJournal.Move move = journal.beginMove(to);
                if (move != null) {
                    moves.add(JournalMove.forJournal(journal, move));
                }
            }
            return moves;
        } catch (IOException | RuntimeException | Error e) {
            rollbackJournalMoves(moves, e);
            throw e;
        }
    }

    /**
     * Completes the journal moves prepared for a successful ciphertext rename.
     *
     * @param moves the pending moves
     * @return the first failure, or {@code null}
     */
    private static @Nullable IOException commitJournalMoves(List<JournalMove> moves) {
        IOException failure = null;
        for (JournalMove move : moves) {
            try {
                move.commit();
            } catch (IOException e) {
                if (failure == null) {
                    failure = e;
                } else {
                    failure.addSuppressed(e);
                }
            }
        }
        return failure;
    }

    /**
     * Rolls back the journal moves prepared for a failed ciphertext rename.
     *
     * @param moves the pending moves
     * @param cause the failure to attach rollback errors to
     */
    private static void rollbackJournalMoves(List<JournalMove> moves, Throwable cause) {
        for (JournalMove move : moves) {
            try {
                move.rollback();
            } catch (IOException e) {
                cause.addSuppressed(e);
            }
        }
    }

    /**
     * Maps a ciphertext path under a renamed source to its new path.
     *
     * @param from the source ciphertext path
     * @param to   the target ciphertext path
     * @param path the ciphertext path below the source
     * @return the path after the rename
     */
    private static String renamedCipherPath(String from, String to, String path) {
        return path.equals(from) ? to : to + path.substring(from.length());
    }

    /**
     * Drops the journal of a deleted ciphertext file, including a pending one
     * left by an open handle. An open handle may keep writing to the unlinked
     * file, so its journal is disabled rather than left at a name that can be
     * reused.
     *
     * @param cipherPath the deleted ciphertext path
     * @throws IOException on filesystem errors
     */
    private void forgetJournal(String cipherPath) throws IOException {
        SharedCipherFile.Entry entry = sharedFiles.get(cipherPath);
        if (entry != null) {
            synchronized (entry.lock) {
                CipherFile file = entry.file;
                if (file != null) {
                    file.forgetJournal();
                    return;
                }
            }
        }
        new CipherJournal(store, cipherPath).clear();
    }

    /**
     * One prepared journal relocation, either through an open {@link CipherFile}
     * or a standalone journal for a path without an open backing file.
     */
    private static final class JournalMove {

        /** The open file whose journal moves, or {@code null}. */
        private final @Nullable CipherFile file;

        /** The standalone journal, or {@code null}. */
        private final @Nullable CipherJournal journal;

        /** The pending move. */
        private final CipherJournal.Move move;

        /**
         * Creates a move for an open file.
         *
         * @param file the open file
         * @param move the pending move
         * @return the journal move
         */
        static JournalMove forFile(CipherFile file, CipherJournal.Move move) {
            return new JournalMove(file, null, move);
        }

        /**
         * Creates a move for a standalone journal.
         *
         * @param journal the standalone journal
         * @param move    the pending move
         * @return the journal move
         */
        static JournalMove forJournal(CipherJournal journal, CipherJournal.Move move) {
            return new JournalMove(null, journal, move);
        }

        private JournalMove(@Nullable CipherFile file, @Nullable CipherJournal journal,
                            CipherJournal.Move move) {
            this.file = file;
            this.journal = journal;
            this.move = move;
        }

        /**
         * Completes this move.
         *
         * @throws IOException on filesystem errors
         */
        void commit() throws IOException {
            if (file != null) {
                file.commitJournalMove(move);
            } else if (journal != null) {
                journal.commitMove(move);
            }
        }

        /**
         * Rolls back this move.
         *
         * @throws IOException on filesystem errors
         */
        void rollback() throws IOException {
            if (file != null) {
                file.rollbackJournalMove(move);
            } else if (journal != null) {
                journal.rollbackMove(move);
            }
        }
    }

    /**
     * Acquires exclusive access to every channel operation. The caller must
     * keep the returned lock until it has flushed the shared files and either
     * aborted the close or marked the channels closed and wiped the keys, then
     * release it.
     *
     * @return the held close lock
     */
    Lock lockChannelsForClose() {
        Lock lock = channelGuard.writeLock();
        lock.lock();
        return lock;
    }

    /**
     * Marks the channel guard closed so no further channel operation can start.
     * The caller must hold the lock returned by {@link #lockChannelsForClose()}.
     */
    void markChannelsClosed() {
        channelGuard.markClosed();
    }

    /**
     * Flushes any pending buffered block of every shared cipher file and forces
     * writable files to stable storage. Called before the content-encryption
     * keys are wiped on close, so that buffered plaintext is still encrypted and
     * written while the keys are valid and a failed flush can abort the close
     * for a retry.
     *
     * @throws IOException on filesystem or encryption errors
     */
    void flushSharedFiles() throws IOException {
        IOException failure = null;
        for (SharedCipherFile.Entry entry : openEntries) {
            try {
                SharedCipherFile.flushEntry(entry);
                SharedCipherFile.forceEntry(entry);
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
     * Closes every shared cipher file, wiping its block cache and the
     * content-encryption key of its backing file, so no derived content key
     * survives a filesystem close even when handles are still open. The
     * underlying store is not closed.
     *
     * @throws IOException on filesystem errors while closing a file
     */
    void closeSharedFiles() throws IOException {
        IOException failure = null;
        for (SharedCipherFile.Entry entry : openEntries) {
            try {
                SharedCipherFile.closeEntry(entry);
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
        long size = contentGeometry.cipherSizeToPlainSize(cipherSize);
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
        synchronized (fileLock(r.cipherPath())) {
            try (SharedCipherFile cf = openCipherFileByName(r.cipherPath(), false)) {
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
        synchronized (fileLock(r.cipherPath())) {
            try (SharedCipherFile cf = openCipherFileByName(r.cipherPath(), false)) {
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
        SeekableByteChannel ch = openChannel(r.cipherPath(), 0, false);
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
     * <p>Writing starts at the beginning of the file. The content is staged in
     * a hidden sibling file and replaces the target only when the stream is
     * closed successfully, so a crash mid-stream leaves the previous file
     * intact. Call {@link AbortableOutputStream#abort()} to discard a partial
     * write instead of committing it.</p>
     *
     * @param plainFile the plaintext file path
     * @return the encrypting output stream
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    AbortableOutputStream openWrite(String plainFile) throws IOException {
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
    AbortableOutputStream openWrite(String plainFile, SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        // Keep the previous contract: openWrite replaces an existing file
        // rather than creating a missing one.
        store.stat(r.cipherPath());
        String cipherParent = r.cipherParent();
        if (cipherParent == null) {
            throw new IOException("cannot open the cipher root as a file");
        }
        String tempCipherPath = PathResolver.join(cipherParent,
                Constants.INTERNAL_NAME_PREFIX + "-write-" + UUID.randomUUID());
        SharedCipherFile cf = null;
        SeekableByteChannel ch = null;
        AtomicWriteOutputStream result = null;
        try {
            store.createFile(tempCipherPath);
            copyWriteAttributes(r.cipherPath(), tempCipherPath);
            cf = openCipherFileByName(tempCipherPath, true, syncPolicy);
            ch = cf.newChannel(0, true, syncPolicy);
            result = new AtomicWriteOutputStream(Channels.newOutputStream(ch), ch,
                    tempCipherPath, r.cipherPath());
            cf.close();
            return result;
        } catch (IOException | RuntimeException | Error e) {
            if (result != null) {
                try {
                    result.abort();
                } catch (IOException cleanup) {
                    e.addSuppressed(cleanup);
                }
            } else if (ch != null) {
                try {
                    ch.close();
                } catch (IOException cleanup) {
                    e.addSuppressed(cleanup);
                }
            }
            if (cf != null) {
                try {
                    cf.close();
                } catch (IOException cleanup) {
                    e.addSuppressed(cleanup);
                }
            }
            try {
                IOException cleanup = cleanupWrite(tempCipherPath);
                if (cleanup != null) {
                    e.addSuppressed(cleanup);
                }
            } catch (RuntimeException cleanup) {
                e.addSuppressed(cleanup);
            }
            throw e;
        }
    }

    /**
     * A stream that stages its content in a hidden temporary file and replaces
     * the target only on a successful close.
     */
    private final class AtomicWriteOutputStream extends AbortableOutputStream {

        /** The channel-backed output stream. */
        private final OutputStream out;

        /** The channel whose length is adjusted on close. */
        private final SeekableByteChannel channel;

        /** The hidden ciphertext path holding the staged content. */
        private final String tempCipherPath;

        /** The ciphertext path replaced on a successful close. */
        private final String targetCipherPath;

        /** Whether this stream has been closed or aborted. */
        private boolean closed;

        /** Whether a write, flush or close operation has failed. */
        private boolean failed;

        /**
         * Creates a stream over the given staging channel.
         *
         * @param out              the channel-backed output stream
         * @param channel          the underlying channel
         * @param tempCipherPath   the hidden ciphertext path of the staged content
         * @param targetCipherPath the ciphertext path to replace on success
         */
        AtomicWriteOutputStream(OutputStream out, SeekableByteChannel channel,
                                String tempCipherPath, String targetCipherPath) {
            this.out = out;
            this.channel = channel;
            this.tempCipherPath = tempCipherPath;
            this.targetCipherPath = targetCipherPath;
        }

        @Override
        public void write(int b) throws IOException {
            try {
                out.write(b);
            } catch (IOException | RuntimeException e) {
                failed = true;
                throw e;
            }
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            try {
                out.write(b, off, len);
            } catch (IOException | RuntimeException e) {
                failed = true;
                throw e;
            }
        }

        @Override
        public void flush() throws IOException {
            try {
                out.flush();
            } catch (IOException | RuntimeException e) {
                failed = true;
                throw e;
            }
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            if (failed) {
                IOException cleanup = abortContents();
                if (cleanup != null) {
                    throw cleanup;
                }
                return;
            }
            IOException failure = null;
            try {
                out.flush();
                channel.truncate(channel.position());
            } catch (IOException e) {
                failure = e;
            }
            try {
                out.close();
            } catch (IOException e) {
                if (failure == null) {
                    failure = e;
                } else {
                    failure.addSuppressed(e);
                }
            }
            if (failure != null) {
                IOException cleanup = abortContents();
                if (cleanup != null) {
                    failure.addSuppressed(cleanup);
                }
                throw failure;
            }
            try {
                commitWrite(tempCipherPath, targetCipherPath);
            } catch (IOException | RuntimeException e) {
                IOException cleanup = cleanupWrite(tempCipherPath);
                if (cleanup != null) {
                    e.addSuppressed(cleanup);
                }
                throw e;
            }
        }

        @Override
        public void abort() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            IOException failure = abortContents();
            if (failure != null) {
                throw failure;
            }
        }

        /**
         * Closes the staging channel and removes the staged file.
         *
         * @return the first failure, or {@code null}
         */
        private @Nullable IOException abortContents() {
            IOException failure = null;
            try {
                out.close();
            } catch (IOException e) {
                failure = e;
            }
            IOException cleanup = cleanupWrite(tempCipherPath);
            if (cleanup != null) {
                if (failure == null) {
                    failure = cleanup;
                } else {
                    failure.addSuppressed(cleanup);
                }
            }
            return failure;
        }
    }

    /**
     * Copies the target's POSIX ownership and permissions onto a staged write
     * file, so replacing the target does not widen its access mode.
     *
     * @param targetCipherPath the file being replaced
     * @param tempCipherPath   the hidden staging file
     * @throws IOException on filesystem errors
     */
    private void copyWriteAttributes(String targetCipherPath, String tempCipherPath)
            throws IOException {
        PosixFileAttributes attributes = store.posixAttributes(targetCipherPath);
        if (attributes == null) {
            return;
        }
        try {
            store.setPosixPermissions(tempCipherPath, attributes.permissions());
            store.setPosixOwner(tempCipherPath, attributes.owner());
            store.setPosixGroup(tempCipherPath, attributes.group());
        } catch (UnsupportedOperationException ignored) {
            // A store may expose attributes without allowing them to be set.
        }
    }

    /**
     * Removes a staged write file and its journal, releasing any shared entry.
     *
     * @param tempCipherPath the hidden staging path
     * @return the first cleanup failure, or {@code null}
     */
    private @Nullable IOException cleanupWrite(String tempCipherPath) {
        releaseSharedFile(tempCipherPath);
        IOException failure = null;
        try {
            new CipherJournal(store, tempCipherPath).clear();
        } catch (IOException e) {
            failure = e;
        }
        try {
            deleteIfExists(store, tempCipherPath);
        } catch (IOException e) {
            if (failure == null) {
                failure = e;
            } else {
                failure.addSuppressed(e);
            }
        }
        return failure;
    }

    /**
     * Replaces the target with the staged write file. A journal left by an
     * earlier in-place update of the old target is removed because the staged
     * file replaces it completely.
     *
     * @param tempCipherPath   the hidden staging path
     * @param targetCipherPath the target to replace
     * @throws IOException on filesystem errors
     */
    private void commitWrite(String tempCipherPath, String targetCipherPath) throws IOException {
        synchronized (fileLock(targetCipherPath)) {
            // Drop the old registry entry so later opens see the replacement;
            // handles already open keep their reference to the old file.
            SharedCipherFile.Entry replaced = sharedFiles.get(targetCipherPath);
            releaseSharedFile(targetCipherPath);
            releaseSharedFile(tempCipherPath);
            Lock channelLock = channelGuard.writeLock();
            channelLock.lock();
            try {
                store.rename(tempCipherPath, targetCipherPath, true);
                // A handle on the replaced target may still be open. Its
                // journal is now at the new file's path, so disable it before
                // that handle can publish a journal for the wrong file.
                if (replaced != null) {
                    synchronized (replaced.lock) {
                        CipherFile file = replaced.file;
                        if (file != null) {
                            file.forgetJournal();
                        } else {
                            new CipherJournal(store, targetCipherPath).clear();
                        }
                    }
                } else {
                    new CipherJournal(store, targetCipherPath).clear();
                }
            } finally {
                channelLock.unlock();
            }
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
        synchronized (fileLock(r.cipherPath())) {
            try (SeekableByteChannel ch = openChannel(r.cipherPath(), offset, true, syncPolicy)) {
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
        synchronized (fileLock(r.cipherPath())) {
            try (SharedCipherFile cf = openCipherFileByName(r.cipherPath(), true, syncPolicy)) {
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
        store.setTimes(r.cipherPath(), lastModifiedTime, lastAccessTime, createTime);
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
        store.checkAccess(r.cipherPath(), modes);
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
        return store.posixAttributes(r.cipherPath());
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
        store.setPosixPermissions(r.cipherPath(), permissions);
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
        store.setPosixOwner(r.cipherPath(), owner);
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
        store.setPosixGroup(r.cipherPath(), group);
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
            store.createFile(r.cipherPath());
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
            store.mkdir(r.cipherPath());
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                nameManager.removeLongName(r);
            }
            throw e;
        }
        try {
            directoryManager.writeDirIV(r.cipherPath());
        } catch (IOException | RuntimeException e) {
            try {
                deleteIfExists(store, PathResolver.join(r.cipherPath(), Constants.DIR_IV_FILENAME));
                store.delete(r.cipherPath());
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
        // Wait for in-flight channel I/O and keep new I/O out until the entry
        // is unlinked and its journal is gone. Otherwise a write that started
        // before the delete could publish a journal after the file was
        // unlinked, and that journal could be replayed for a later file at the
        // same path.
        Lock channelLock = channelGuard.writeLock();
        channelLock.lock();
        try {
            if (store.stat(r.cipherPath()).isDirectory()) {
                cleanupInternalEntries(r.cipherPath());
                removeEmptyDir(r.cipherPath());
            } else {
                store.delete(r.cipherPath());
                forgetJournal(r.cipherPath());
            }
            releaseSharedFile(r.cipherPath());
            nameManager.removeLongName(r);
            directoryManager.invalidateDirIvCache(r.cipherPath());
        } finally {
            channelLock.unlock();
        }
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
        // Exclude in-flight channel I/O across the path move so no write can
        // publish a journal for the old path after the file has moved.
        Lock channelLock = channelGuard.writeLock();
        channelLock.lock();
        try {
            renameLocked(plainFrom, plainTo, replaceExisting);
        } finally {
            channelLock.unlock();
        }
    }

    /**
     * Performs the rename while the channel write lock excludes channel I/O.
     *
     * @param plainFrom       the plaintext source path
     * @param plainTo         the plaintext target path
     * @param replaceExisting whether an existing target may be replaced
     * @throws IOException on filesystem errors
     */
    private void renameLocked(String plainFrom, String plainTo, boolean replaceExisting)
            throws IOException {
        List<String> fromComps = PathResolver.normalize(plainFrom);
        List<String> toComps = PathResolver.normalize(plainTo);
        if (fromComps.isEmpty() || toComps.isEmpty()) {
            throw new IOException("cannot rename the root directory");
        }
        PathResolver.Resolved from = pathResolver.resolveParent(plainFrom);
        CipherNode fromNode;
        try {
            fromNode = store.stat(from.cipherPath());
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
        if (exists(to.cipherPath())) {
            if (!replaceExisting) {
                throw new FileAlreadyExistsException(plainTo);
            }
            if (store.stat(to.cipherPath()).isDirectory()) {
                // A directory can only be replaced by another directory, and
                // only when it is empty apart from its gocryptfs.diriv. Verify
                // both before removing anything so a rejected replace leaves the
                // target intact.
                verifyEmptyDir(to.cipherPath());
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
                    movedDirIV = directoryManager.moveDirIVAside(to.cipherPath());
                }
            }
            // A non-directory target is replaced atomically by the rename below.
        }
        boolean wroteName = false;
        List<JournalMove> journalMoves = new ArrayList<>();
        try {
            wroteName = nameManager.prepareLongName(to);
            journalMoves = prepareJournalMoves(from.cipherPath(), to.cipherPath());
            store.rename(from.cipherPath(), to.cipherPath(), replaceExisting);
        } catch (IOException | RuntimeException e) {
            rollbackJournalMoves(journalMoves, e);
            // Restore the target's diriv so a failed directory replace leaves
            // the target directory intact.
            if (movedDirIV != null) {
                try {
                    directoryManager.restoreDirIV(to.cipherPath(), movedDirIV);
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
        IOException journalFailure = commitJournalMoves(journalMoves);
        if (movedDirIV != null) {
            try {
                deleteIfExists(store, movedDirIV);
            } catch (IOException cleanup) {
                // The replace succeeded; only the moved-aside diriv is left.
            }
        }
        nameManager.removeLongName(from);
        moveSharedFile(from.cipherPath(), to.cipherPath());
        directoryManager.invalidateDirIvCache(from.cipherPath());
        directoryManager.invalidateDirIvCache(to.cipherPath());
        if (journalFailure != null) {
            throw journalFailure;
        }
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
        ContentEnc enc = contentEncFactory.get();
        try {
            return readSymlink(cipherSymlink, store, enc, nameTransform, plaintextNames);
        } finally {
            enc.wipe();
        }
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
        return readSymlink(r.cipherPath());
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
        ContentEnc enc = contentEncFactory.get();
        try {
            String cTarget = encryptSymlinkTarget(target, enc, nameTransform, plaintextNames);
            store.createSymlink(r.cipherPath(), cTarget);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                nameManager.removeLongName(r);
            }
            throw e;
        } finally {
            enc.wipe();
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

    /** Prefix of the hidden staging file used by {@link #openWrite(String)}. */
    private static final String WRITE_TEMP_PREFIX =
            Constants.INTERNAL_NAME_PREFIX + "-write-";

    /**
     * Removes stale internal artifacts left behind by a crash: atomic-write
     * temporaries, abandoned streaming-write staging files, and journals whose
     * cipher file no longer exists. This runs only for a writable filesystem,
     * under the cipher root lock, so another writer cannot be using them.
     *
     * <p>A journal for an existing cipher file is intentionally kept: opening
     * that file replays it. Journals are named after their cipher file, so a
     * journal with no matching regular file in the same directory is an orphan
     * (for example the file was deleted before the journal was removed).</p>
     *
     * @throws IOException on filesystem errors
     */
    void cleanupOrphans() throws IOException {
        cleanupOrphans(store.root());
    }

    /**
     * Recursively removes stale internal artifacts below a cipher directory.
     *
     * @param dir the cipher directory
     * @throws IOException on filesystem errors
     */
    private void cleanupOrphans(String dir) throws IOException {
        List<CipherNode> entries = store.list(dir);
        cleanupInternalEntries(dir, entries);
        for (CipherNode entry : entries) {
            if (entry.isDirectory()
                    && !entry.name().startsWith(Constants.INTERNAL_NAME_PREFIX)) {
                cleanupOrphans(PathResolver.join(dir, entry.name()));
            }
        }
    }

    /**
     * Removes stale internal files directly inside one cipher directory.
     *
     * @param dir the cipher directory
     * @throws IOException on filesystem errors
     */
    private void cleanupInternalEntries(String dir) throws IOException {
        cleanupInternalEntries(dir, store.list(dir));
    }

    /**
     * Removes stale internal files directly inside one cipher directory, given
     * its current listing.
     *
     * @param dir     the cipher directory
     * @param entries the directory listing
     * @throws IOException on filesystem errors
     */
    private void cleanupInternalEntries(String dir, List<CipherNode> entries)
            throws IOException {
        List<String> journals = new ArrayList<>();
        for (CipherNode entry : entries) {
            if (entry.isDirectory()) {
                continue;
            }
            String name = entry.name();
            if (!name.startsWith(Constants.INTERNAL_NAME_PREFIX)) {
                continue;
            }
            String path = PathResolver.join(dir, name);
            if (name.endsWith(".tmp") || name.startsWith(WRITE_TEMP_PREFIX)) {
                deleteIfExists(store, path);
                if (name.startsWith(WRITE_TEMP_PREFIX)) {
                    deleteIfExists(store, CipherJournal.journalName(path));
                }
            } else if (CipherJournal.isJournalName(name)) {
                journals.add(name);
            }
        }
        if (journals.isEmpty()) {
            return;
        }
        Set<String> expected = new HashSet<>();
        for (CipherNode entry : entries) {
            if (entry.isRegularFile()
                    && !entry.name().startsWith(Constants.INTERNAL_NAME_PREFIX)) {
                String path = PathResolver.join(dir, entry.name());
                expected.add(PathResolver.baseName(CipherJournal.journalName(path)));
            }
        }
        for (String journal : journals) {
            if (!expected.contains(journal)) {
                deleteIfExists(store, PathResolver.join(dir, journal));
            }
        }
    }

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
