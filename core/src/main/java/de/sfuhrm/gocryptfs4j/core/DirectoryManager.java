package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages per-directory IVs and the listing of ciphertext directories.
 *
 * <p>Owns the {@code gocryptfs.diriv} handling (read, write and caching) that
 * provides the IV for name encryption within each directory, and turns a
 * ciphertext directory listing into the plaintext {@link DirEntry}s exposed by
 * the filesystem, resolving long names and skipping corrupt entries.</p>
 */
final class DirectoryManager {

    /** The ciphertext-side store. */
    private final CipherStore store;

    /** The ciphertext root name. */
    private final String rootName;

    /** Whether file names are stored unencrypted. */
    private final boolean plaintextNames;

    /** Whether deterministic (no per-directory IV) name encryption is used. */
    private final boolean deterministicNames;

    /** The name-transform helper. */
    private final NameTransform nameTransform;

    /** The content-encryption helper. */
    private final ContentEnc contentEnc;

    /** The name manager. */
    private final NameManager nameManager;

    /**
     * The file manager, used to resolve the write-back-aware plaintext size of
     * listed files. Set after construction, once the file manager exists, so it
     * is {@code null} in tests that construct the directory manager alone.
     */
    private @Nullable FileManager fileManager;

    /** Cache of per-directory IVs, keyed by cipher directory name. */
    private final Map<String, byte[]> dirIvCache = new ConcurrentHashMap<>();

    /**
     * Creates a directory manager.
     *
     * @param store              the ciphertext-side store
     * @param rootName           the ciphertext root name
     * @param plaintextNames     whether file names are stored unencrypted
     * @param deterministicNames whether deterministic name encryption is used
     * @param nameTransform      the name-transform helper
     * @param contentEnc         the content-encryption helper
     * @param nameManager        the name manager
     * @throws NullPointerException if a required argument is {@code null}
     */
    DirectoryManager(CipherStore store, String rootName, boolean plaintextNames,
                     boolean deterministicNames, NameTransform nameTransform,
                     ContentEnc contentEnc, NameManager nameManager) {
        this.store = Objects.requireNonNull(store, "store");
        this.rootName = Objects.requireNonNull(rootName, "rootName");
        this.plaintextNames = plaintextNames;
        this.deterministicNames = deterministicNames;
        this.nameTransform = Objects.requireNonNull(nameTransform, "nameTransform");
        this.contentEnc = Objects.requireNonNull(contentEnc, "contentEnc");
        this.nameManager = Objects.requireNonNull(nameManager, "nameManager");
    }

    /**
     * Supplies the file manager so listed file sizes account for unflushed
     * write-back data. Called once, after the file manager is constructed.
     *
     * @param fileManager the file manager
     */
    void setFileManager(FileManager fileManager) {
        this.fileManager = Objects.requireNonNull(fileManager, "fileManager");
    }

    /**
     * Reads the {@code gocryptfs.diriv} of {@code cipherDir} without ever
     * creating it. A missing diriv in an empty directory is reported as a
     * fresh, unpersisted IV so that read-only operations (for example listing)
     * do not write to the cipher directory; this is also what keeps a live
     * gocryptfs mount from racing with a concurrent {@code mkdir}, which
     * creates the diriv itself with an exclusive create.
     *
     * @param cipherDir the ciphertext directory name
     * @return the 16-byte directory IV
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} is {@code null}
     */
    byte[] readDirIV(String cipherDir) throws IOException {
        return readDirIV(cipherDir, false);
    }

    /**
     * Reads the {@code gocryptfs.diriv} of {@code cipherDir}, optionally
     * minting and persisting a fresh one when it is missing and the directory
     * is empty.
     *
     * @param cipherDir the ciphertext directory name
     * @param create    whether to create a missing diriv for an empty directory
     * @return the 16-byte directory IV
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} is {@code null}
     */
    byte[] readDirIV(String cipherDir, boolean create) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        if (plaintextNames) {
            return new byte[Constants.DIR_IV_LEN];
        }
        if (deterministicNames) {
            return nameTransform.zeroDirIV();
        }
        byte[] cached = dirIvCache.get(cipherDir);
        if (cached != null) {
            return cached.clone();
        }
        byte[] data = readDirIVInternal(cipherDir, create);
        if (data == null) {
            // The directory is empty and has no diriv. In read mode, or when
            // the repair cannot be persisted (for example on a read-only
            // medium), return a fresh, unpersisted IV. There are no names to
            // decrypt, so this is safe for listing; it is deliberately not
            // cached so a later read re-attempts once the diriv appears.
            return Keys.randomBytes(Constants.DIR_IV_LEN);
        }
        if (data.length != Constants.DIR_IV_LEN) {
            throw new IOException("bad diriv length " + data.length + " in " + cipherDir);
        }
        for (byte b : data) {
            if (b != 0) {
                dirIvCache.put(cipherDir, data);
                return data.clone();
            }
        }
        throw new IOException("diriv is all-zero in " + cipherDir);
    }

    /**
     * Reads the {@code gocryptfs.diriv} of {@code cipherDir}, minting and
     * persisting a fresh one when {@code create} is set and the file is missing
     * and the directory is empty.
     *
     * <p>A crash between {@code mkdir} and {@code writeDirIV} (or a directory
     * created by an older gocryptfs) can leave a directory without a
     * {@code gocryptfs.diriv}. Such a directory is empty &mdash; no entry can be
     * created under it while its diriv is missing &mdash; so minting a fresh
     * random IV makes the directory usable again. This repair is performed only
     * when explicitly requested (opt-in, from write paths), never as a side
     * effect of a read. A directory that already has entries but no diriv was
     * encrypted under an IV that is no longer available, so minting a fresh IV
     * would make those names undecryptable; it is rejected instead.</p>
     *
     * <p>Control files do not count as entries here: the root's
     * {@code gocryptfs.conf} and the directory's own (missing) diriv are not
     * encrypted user names, so a root left with only a config file can still
     * be repaired. The repair also requires a strongly consistent listing (see
     * {@link CipherStore#isListingConsistent()}); on an eventually consistent
     * store a stale empty listing must not be trusted to mint a new IV, so the
     * repair is refused instead.</p>
     *
     * @param cipherDir the ciphertext directory name
     * @param create    whether to mint and persist a missing diriv for an empty
     *                  directory
     * @return the 16-byte directory IV, or {@code null} if the directory is
     *         empty and no diriv is available (because {@code create} is false,
     *         or because a fresh IV could not be persisted on a read-only
     *         medium)
     * @throws IOException on filesystem errors, a corrupt diriv, a missing
     *                     diriv in a non-empty directory, or a repair attempt
     *                     on a store with an inconsistent listing
     */
    private byte @Nullable [] readDirIVInternal(String cipherDir, boolean create) throws IOException {
        String path = PathResolver.join(cipherDir, Constants.DIR_IV_FILENAME);
        try {
            return store.readSmall(path, Constants.DIR_IV_LEN);
        } catch (NoSuchFileException e) {
            if (hasNonControlEntries(cipherDir)) {
                throw new IOException("directory has entries but no gocryptfs.diriv: " + cipherDir);
            }
            if (!create) {
                return null;
            }
            if (!store.isListingConsistent()) {
                throw new IOException("cannot repair missing gocryptfs.diriv in " + cipherDir
                        + ": the store does not provide a consistent directory listing");
            }
            byte[] iv = Keys.randomBytes(Constants.DIR_IV_LEN);
            try {
                store.writeSmall(path, iv, false);
            } catch (FileAlreadyExistsException ignored) {
                // Another handle created the directory's diriv concurrently;
                // the read below returns whichever diriv is there now.
            } catch (IOException writeFailure) {
                // The directory is empty but the repair cannot be persisted
                // (for example the store is read-only). Return null so the
                // caller can list it as empty rather than failing.
                return null;
            }
            return store.readSmall(path, Constants.DIR_IV_LEN);
        }
    }

    /**
     * Returns whether {@code cipherDir} contains any entry that is not a
     * control file.
     *
     * <p>The per-directory {@code gocryptfs.diriv} is a control file when this
     * filesystem uses one, and the root's {@code gocryptfs.conf} is a control
     * file as well. Neither represents a name encrypted under the directory
     * IV, so neither prevents a missing diriv from being repaired. Long-name
     * support files are deliberately counted: they belong to user entries.</p>
     *
     * @param cipherDir the ciphertext directory name
     * @return {@code true} if a non-control entry exists
     * @throws IOException on filesystem errors
     */
    private boolean hasNonControlEntries(String cipherDir) throws IOException {
        boolean isRoot = cipherDir.equals(rootName);
        for (CipherNode node : store.list(cipherDir)) {
            String name = node.name();
            if (usesDirIV() && name.equals(Constants.DIR_IV_FILENAME)) {
                continue;
            }
            if (isRoot && name.equals(Constants.CONF_DEFAULT_NAME)) {
                continue;
            }
            return true;
        }
        return false;
    }

    /**
     * Returns whether the filesystem uses per-directory {@code gocryptfs.diriv}
     * files. This is false in plaintext-names mode and in deterministic-names
     * mode, where an entry named {@code gocryptfs.diriv} is an ordinary user
     * entry rather than a control file.
     *
     * @return {@code true} if a per-directory IV file is used
     */
    boolean usesDirIV() {
        return !plaintextNames && !deterministicNames;
    }

    /**
     * Creates a {@code gocryptfs.diriv} in {@code cipherDir}, failing if one
     * already exists.
     *
     * @param cipherDir the ciphertext directory name
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} is {@code null}
     */
    void writeDirIV(String cipherDir) throws IOException {
        writeDirIV(cipherDir, false);
    }

    /**
     * Creates a {@code gocryptfs.diriv} in {@code cipherDir}.
     *
     * <p>During filesystem creation the config file is the commit marker and
     * is written after the diriv, so a crash can leave an orphan diriv behind.
     * Creation passes {@code overwrite = true} to replace such an orphan; all
     * other callers keep the exclusive-create behaviour that protects a live
     * directory's IV.</p>
     *
     * @param cipherDir the ciphertext directory name
     * @param overwrite whether to replace an existing diriv
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} is {@code null}
     */
    void writeDirIV(String cipherDir, boolean overwrite) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        if (!usesDirIV()) {
            return;
        }
        store.writeSmall(PathResolver.join(cipherDir, Constants.DIR_IV_FILENAME),
                Keys.randomBytes(Constants.DIR_IV_LEN), overwrite);
        dirIvCache.remove(cipherDir);
    }

    /**
     * Writes {@code iv} as the {@code gocryptfs.diriv} of {@code cipherDir},
     * replacing any existing file. Used to restore the directory IV after a
     * failed directory removal so the names in the directory stay decryptable.
     *
     * @param cipherDir the ciphertext directory name
     * @param iv        the 16-byte directory IV
     * @throws IOException on filesystem errors
     * @throws NullPointerException if an argument is {@code null}
     */
    void restoreDirIV(String cipherDir, byte[] iv) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        Objects.requireNonNull(iv, "iv");
        if (!usesDirIV()) {
            return;
        }
        store.writeSmall(PathResolver.join(cipherDir, Constants.DIR_IV_FILENAME), iv.clone(), true);
        dirIvCache.put(cipherDir, iv.clone());
    }

    /**
     * Removes any cached directory IVs at or below {@code dir}.
     *
     * @param dir the cipher directory whose subtree is no longer valid
     */
    void invalidateDirIvCache(String dir) {
        if (dirIvCache.isEmpty()) {
            return;
        }
        dirIvCache.keySet().removeIf(k -> k.equals(dir) || k.startsWith(dir + "/"));
    }

    /**
     * Clears the directory-IV cache, wiping the cached IVs.
     */
    void clearDirIvCache() {
        dirIvCache.clear();
    }

    /**
     * Captures the ciphertext listing of a directory without decrypting any
     * entry name.
     *
     * <p>Long names are resolved to their full ciphertext name so that a later
     * change can still be decrypted after the long-name support file is gone.
     * Control files (the per-directory {@code gocryptfs.diriv} and the root's
     * {@code gocryptfs.conf}) and long-name support files are excluded, just as
     * in {@link #listCipherDir(String, byte[])}.</p>
     *
     * @param cipherDir the ciphertext directory name
     * @return the snapshot of the directory
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} is {@code null}
     */
    DirectorySnapshot snapshotDirectory(String cipherDir) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        Map<String, DirectorySnapshot.Entry> entries = new HashMap<>();
        boolean isRoot = cipherDir.equals(rootName);
        for (CipherNode node : store.list(cipherDir)) {
            String storageName = node.name();
            if (usesDirIV() && storageName.equals(Constants.DIR_IV_FILENAME)) {
                continue;
            }
            if (isRoot && storageName.equals(Constants.CONF_DEFAULT_NAME)) {
                continue;
            }

            String cipherName = storageName;
            if (!plaintextNames) {
                int type = nameManager.nameType(storageName);
                if (type == NameTransform.LONG_NAME_FILENAME) {
                    continue;
                }
                if (type == NameTransform.LONG_NAME_CONTENT) {
                    try {
                        cipherName = nameManager.resolveLongName(cipherDir, storageName);
                    } catch (IOException e) {
                        // Treat an unreadable long-name support file like the
                        // listing does: skip the corrupt entry.
                        continue;
                    }
                }
            }
            entries.put(storageName, new DirectorySnapshot.Entry(storageName, cipherName,
                    node.kind(), node.size(), node.lastModifiedTime()));
        }
        return new DirectorySnapshot(this, cipherDir, entries);
    }

    /**
     * Decrypts a single ciphertext name using the directory IV.
     *
     * @param cipherDir  the ciphertext directory name
     * @param cipherName the ciphertext name
     * @return the plaintext name
     * @throws IOException on filesystem errors
     * @throws IllegalArgumentException if the name cannot be decrypted
     * @throws NullPointerException if an argument is {@code null}
     */
    String plainNameForCipher(String cipherDir, String cipherName) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        Objects.requireNonNull(cipherName, "cipherName");
        return nameManager.plainNameFor(cipherName, readDirIV(cipherDir));
    }

    /**
     * Lists a cipher-side directory, decrypting names and resolving long names.
     *
     * <p>Corrupt entries &mdash; undecryptable names, unreadable long-name
     * support files, names that are unsafe in plaintext space and unreadable
     * symlink targets &mdash; are skipped rather than aborting the listing.</p>
     *
     * @param cipherDir the ciphertext directory name
     * @param iv        the 16-byte directory IV
     * @return the directory entries
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} or {@code iv} is {@code null}
     */
    List<DirEntry> listCipherDir(String cipherDir, byte[] iv) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        Objects.requireNonNull(iv, "iv");
        List<DirEntry> out = new ArrayList<>();
        boolean isRoot = cipherDir.equals(rootName);
        for (CipherNode node : store.list(cipherDir)) {
            String cName = node.name();
            if (usesDirIV() && cName.equals(Constants.DIR_IV_FILENAME)) {
                continue;
            }
            if (isRoot && cName.equals(Constants.CONF_DEFAULT_NAME)) {
                continue;
            }

            String cipherName = cName;
            if (!plaintextNames) {
                int t = nameManager.nameType(cName);
                if (t == NameTransform.LONG_NAME_FILENAME) {
                    continue;
                }
                if (t == NameTransform.LONG_NAME_CONTENT) {
                    try {
                        cipherName = nameManager.resolveLongName(cipherDir, cName);
                    } catch (IOException e) {
                        // A missing, oversized or otherwise unreadable .name
                        // file is treated like a corrupt name: skip it.
                        continue;
                    }
                }
            }

            String plainName;
            try {
                plainName = nameManager.plainNameFor(cipherName, iv);
            } catch (IllegalArgumentException e) {
                // Skip undecryptable (corrupt) entries.
                continue;
            }
            if (!NameManager.isValidPlainName(plainName)) {
                // Skip names that would escape the directory in plaintext
                // space (e.g. "..", "/" or a NUL byte).
                continue;
            }

            DirEntry.Kind kind;
            long size;
            if (node.isDirectory()) {
                kind = DirEntry.Kind.DIRECTORY;
                size = 0;
            } else if (node.isSymbolicLink()) {
                kind = DirEntry.Kind.SYMLINK;
                String target;
                try {
                    target = FileManager.readSymlink(PathResolver.join(cipherDir, cName),
                            store, contentEnc, nameTransform, plaintextNames);
                } catch (IOException | IllegalArgumentException e) {
                    // A corrupt (undecodable or undecryptable) symlink target
                    // is treated like a corrupt name: skip it.
                    continue;
                }
                size = target.getBytes(StandardCharsets.UTF_8).length;
            } else if (node.isRegularFile()) {
                kind = DirEntry.Kind.FILE;
                if (fileManager != null) {
                    size = fileManager.plainSizeIncludingWriteBack(
                            PathResolver.join(cipherDir, cName), node.size());
                } else {
                    size = contentEnc.cipherSizeToPlainSize(node.size());
                }
            } else {
                kind = DirEntry.Kind.OTHER;
                size = node.size();
            }

            out.add(new DirEntry(plainName, cName, null, kind, size,
                    node.lastModifiedTime(), node.lastAccessTime(),
                    node.creationTime(), node.fileKey()));
        }
        return out;
    }
}
