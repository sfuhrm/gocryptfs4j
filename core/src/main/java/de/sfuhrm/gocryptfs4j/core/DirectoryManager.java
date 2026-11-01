package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.util.ArrayList;
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
     * Reads the {@code gocryptfs.diriv} of {@code cipherDir}.
     *
     * @param cipherDir the ciphertext directory name
     * @return the 16-byte directory IV
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} is {@code null}
     */
    byte[] readDirIV(String cipherDir) throws IOException {
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
        byte[] data = readOrCreateDirIV(cipherDir);
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
     * persisting a fresh one if the file is missing.
     *
     * <p>A crash between {@code mkdir} and {@code writeDirIV} (or a directory
     * created by an older gocryptfs) can leave a directory without a
     * {@code gocryptfs.diriv}. Such a directory is empty &mdash; no entry can be
     * created under it while its diriv is missing &mdash; so minting a fresh
     * random IV here is safe and makes the directory usable again.</p>
     *
     * @param cipherDir the ciphertext directory name
     * @return the 16-byte directory IV
     * @throws IOException on filesystem errors or a corrupt diriv
     */
    private byte[] readOrCreateDirIV(String cipherDir) throws IOException {
        String path = PathResolver.join(cipherDir, Constants.DIR_IV_FILENAME);
        try {
            return store.readSmall(path, Constants.DIR_IV_LEN);
        } catch (NoSuchFileException e) {
            byte[] iv = Keys.randomBytes(Constants.DIR_IV_LEN);
            try {
                store.writeSmall(path, iv, false);
            } catch (FileAlreadyExistsException ignored) {
                // Another handle repaired the directory concurrently; the write
                // below returns whichever diriv is there now.
            }
            return store.readSmall(path, Constants.DIR_IV_LEN);
        }
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
     * Creates a {@code gocryptfs.diriv} in {@code cipherDir}.
     *
     * @param cipherDir the ciphertext directory name
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} is {@code null}
     */
    void writeDirIV(String cipherDir) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        if (!usesDirIV()) {
            return;
        }
        store.writeSmall(PathResolver.join(cipherDir, Constants.DIR_IV_FILENAME),
                Keys.randomBytes(Constants.DIR_IV_LEN), false);
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
            if (cName.equals(Constants.DIR_IV_FILENAME)) {
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
                size = contentEnc.cipherSizeToPlainSize(node.size());
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
