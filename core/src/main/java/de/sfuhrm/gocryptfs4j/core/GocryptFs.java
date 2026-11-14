package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.config.ConfigFile;
import de.sfuhrm.gocryptfs4j.config.Fido2Params;
import de.sfuhrm.gocryptfs4j.crypto.AesBlockCipher;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.ContentGeometry;
import de.sfuhrm.gocryptfs4j.crypto.Eme;
import de.sfuhrm.gocryptfs4j.crypto.Hkdf;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.CipherStores;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.AccessDeniedException;
import java.nio.file.AccessMode;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * A Java API to a gocryptfs cipher directory.
 *
 * <p>Provides traversal, listing and content read/write on the plaintext view of
 * an encrypted directory using the gocryptfs forward-mode on-disk format.</p>
 *
 * <p>This class operates on a {@link CipherStore}, which supplies the
 * ciphertext-side storage, so the same encrypted data can be stored on the local
 * filesystem (see {@code de.sfuhrm.gocryptfs4j.store.local.PathCipherStore}), a
 * remote filesystem, an object store, or any other backend. A store is either
 * supplied directly to the {@code open}/{@code create} factory methods or
 * resolved from a URI scheme via {@code de.sfuhrm.gocryptfs4j.store.CipherStores}.</p>
 *
 * <p>The work of the filesystem is delegated to a set of single-purpose
 * collaborators: a {@link PathResolver} resolves and validates plaintext paths,
 * a {@link NameManager} handles EME name encryption and long names, a
 * {@link DirectoryManager} manages per-directory IVs and directory listings,
 * and a {@link FileManager} performs file and symlink operations. This class
 * owns the store, configuration and key material and coordinates those
 * collaborators.</p>
 *
 * <p>Store ownership follows who created the store: a store supplied directly to
 * the factory methods is owned by the caller, who must close it when it is no
 * longer needed. A store resolved internally from a URI is owned by the returned
 * instance and is closed by {@link #close()}, so remote backends (the point of
 * the SPI) do not leak connections.</p>
 *
 * <p>A writable instance holds an exclusive writer lock on the store root for
 * its lifetime (see {@link CipherStore#lockRoot()}); opening the same cipher
 * directory for writing a second time fails until the first instance is closed.
 * An instance opened through {@link #openReadOnly} takes no lock and rejects
 * every mutating operation, so a reader can coexist with a writer and can use
 * read-only media.</p>
 *
 * <p>Sensitive input buffers supplied by the caller &mdash; the password
 * {@code char[]} and the raw master-key {@code byte[]} &mdash; are read but
 * neither retained nor wiped by this class: the caller keeps ownership of them
 * and should clear them once they are no longer needed. A password is encoded
 * as UTF-8 before it is passed to scrypt, matching the raw bytes gocryptfs
 * reads from a UTF-8 terminal, passfile or extpass program. The master key and
 * the EME name-encryption sub-key are owned by this instance and wiped on
 * {@link #close()}. The content-encryption sub-key is scoped to the resource
 * that requires it: each file, stream and handle derives its own copy and wipes
 * it when it closes. A raw master-key array is
 * cloned internally, so closing the filesystem never modifies the caller's
 * array. Secrets obtained from a {@link Fido2Token} are owned and wiped by
 * this class.</p>
 *
 * <pre>{@code
 * CipherStore store = new PathCipherStore(Paths.get("/data/cipher"));
 * try (GocryptFs fs = GocryptFs.open(store, "password".toCharArray())) {
 *     for (DirEntry e : fs.list("/")) {
 *         System.out.println(e.plainName());
 *     }
 *     byte[] content = fs.readAll("/notes.txt");
 * }
 * }</pre>
 */
public final class GocryptFs implements AutoCloseable {

    /** The ciphertext-side store. */
    private final CipherStore store;

    /**
     * Whether this instance created {@link #store} itself (via the URI-based
     * factories) and must therefore close it on {@link #close()}. A store
     * supplied directly by the caller is owned by the caller, not by this
     * instance.
     */
    private final boolean ownsStore;

    /** The ciphertext root name, as returned by {@link CipherStore#root()}. */
    private final String rootName;

    /** Whether this filesystem was opened read-only. */
    private final boolean readOnly;

    /**
     * The writer lock held for the lifetime of this filesystem, or {@code null}
     * for a read-only instance.
     */
    private final @Nullable CipherRootLock rootLock;

    /** The parsed configuration file. */
    private ConfigFile config;

    /** The 32-byte master key. */
    private final byte[] masterKey;

    /** The EME name-encryption helper. */
    private final Eme eme;

    /** The keyless content block geometry (sizes and offset translation). */
    private final ContentGeometry contentGeometry;

    /** Whether file names are stored unencrypted. */
    private final boolean plaintextNames;

    /** The name manager (EME and long names). */
    private final NameManager nameManager;

    /** The directory manager (diriv and directories). */
    private final DirectoryManager directoryManager;

    /** The path resolver (path resolution and validation). */
    private final PathResolver pathResolver;

    /** The file manager (file operations and symlinks). */
    private final FileManager fileManager;

    /**
     * A single reentrant read/write lock making metadata operations atomic
     * against each other.
     *
     * <p>Read operations (listing, stat, reads and content writes to existing
     * files) take the {@link #readLock()} and may proceed concurrently with one
     * another. Namespace-mutating operations (create, delete, rename, mkdir and
     * open) take the {@link #writeLock()}, which excludes every other
     * operation. Callers that must perform several operations atomically
     * &mdash; for example the NIO provider's check-then-create in
     * {@code newByteChannel} &mdash; may take the exposed locks directly; both
     * are reentrant.</p>
     */
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    /**
     * Whether this filesystem has been closed. Once set, every public
     * operation fails with {@link IllegalStateException} instead of touching
     * wiped key material.
     */
    private volatile boolean closed;

    /** When buffered writes of newly opened handles are flushed to storage. */
    private volatile SyncPolicy syncPolicy = SyncPolicy.ON_CLOSE;

    /**
     * Throws if this filesystem has been closed.
     *
     * @throws IllegalStateException if this filesystem has been closed
     */
    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("filesystem has been closed");
        }
    }

    /**
     * Throws if this filesystem was opened read-only.
     *
     * @throws IOException if this filesystem is read-only
     */
    private void ensureWritable() throws IOException {
        if (readOnly) {
            throw new IOException("filesystem is read-only");
        }
    }

    /**
     * Returns when buffered writes of newly opened handles are flushed to
     * storage. The default is {@link SyncPolicy#ON_CLOSE}.
     *
     * @return the sync policy
     */
    public SyncPolicy getSyncPolicy() {
        return syncPolicy;
    }

    /**
     * Sets when buffered writes of newly opened handles are flushed to storage.
     * Handles that are already open keep the policy they were opened with.
     *
     * @param syncPolicy the sync policy
     * @throws NullPointerException if {@code syncPolicy} is {@code null}
     */
    public void setSyncPolicy(SyncPolicy syncPolicy) {
        this.syncPolicy = Objects.requireNonNull(syncPolicy, "syncPolicy");
        fileManager.setSyncPolicy(syncPolicy);
    }

    /**
     * Sets the sync policy and returns this filesystem.
     *
     * @param syncPolicy the sync policy
     * @return this filesystem
     * @throws NullPointerException if {@code syncPolicy} is {@code null}
     */
    public GocryptFs withSyncPolicy(SyncPolicy syncPolicy) {
        setSyncPolicy(syncPolicy);
        return this;
    }

    /**
     * Closes a resource, ignoring failures.
     *
     * @param closeable the resource to close, or {@code null}
     */
    private static void closeQuietly(@Nullable AutoCloseable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Throwable ignored) {
                // Best-effort cleanup on a failure path.
            }
        }
    }

    /**
     * Deletes the control files this create call actually created, ignoring any
     * failure. Files that already existed (in particular a config written by a
     * concurrent creator that won the race) are never removed. The config is
     * removed first because it is the commit marker: once it is gone the
     * directory can be created again even if a stale diriv is left behind.
     *
     * @param store         the ciphertext-side store
     * @param configName    the ciphertext path of the config file
     * @param configCreated whether this call created the config file
     * @param dirIVCreated  whether this call created the diriv file
     */
    private static void cleanupCreate(CipherStore store, String configName,
                                      boolean configCreated, boolean dirIVCreated) {
        if (configCreated) {
            try {
                FileManager.deleteIfExists(store, configName);
            } catch (Throwable ignored) {
                // Best-effort cleanup on a failure path.
            }
        }
        if (dirIVCreated) {
            try {
                FileManager.deleteIfExists(store,
                        PathResolver.join(store.root(), Constants.DIR_IV_FILENAME));
            } catch (Throwable ignored) {
                // Best-effort cleanup on a failure path.
            }
        }
    }

    /**
     * Returns whether {@code name} exists in the store.
     *
     * @param store the ciphertext-side store
     * @param name  the ciphertext path
     * @return {@code true} if the entry exists
     * @throws IOException if presence cannot be determined
     */
    private static boolean exists(CipherStore store, String name) throws IOException {
        try {
            store.stat(name);
            return true;
        } catch (NoSuchFileException e) {
            return false;
        }
    }

    /**
     * Creates an instance, called after the master key has been unlocked.
     *
     * @param store     the ciphertext-side store
     * @param config    the parsed configuration
     * @param masterKey the 32-byte master key
     */
    private GocryptFs(CipherStore store, ConfigFile config, byte[] masterKey) {
        this(store, config, masterKey, false, false, null);
    }

    /**
     * Creates an instance, called after the master key has been unlocked.
     *
     * @param store     the ciphertext-side store
     * @param config    the parsed configuration
     * @param masterKey the 32-byte master key
     * @param ownsStore whether this instance owns {@code store} and must close
     *                  it on {@link #close()}
     */
    private GocryptFs(CipherStore store, ConfigFile config, byte[] masterKey, boolean ownsStore) {
        this(store, config, masterKey, ownsStore, false, null);
    }

    /**
     * Creates an instance, called after the master key has been unlocked and,
     * for a writable filesystem, the root lock has been acquired.
     *
     * @param store     the ciphertext-side store
     * @param config    the parsed configuration
     * @param masterKey the 32-byte master key
     * @param ownsStore whether this instance owns {@code store} and must close
     *                  it on {@link #close()}
     * @param readOnly  whether the filesystem is read-only
     * @param rootLock  the writer lock, or {@code null} for a read-only instance
     */
    private GocryptFs(CipherStore store, ConfigFile config, byte[] masterKey, boolean ownsStore,
                      boolean readOnly, @Nullable CipherRootLock rootLock) {
        String root = store.root();
        boolean plainNames = config.plaintextNames();
        boolean dirIv = config.dirIv();
        boolean deterministic = !plainNames && !dirIv;

        Eme emeHelper = null;
        boolean constructed = false;
        try {
            boolean useHkdf = config.hkdf();
            byte[] emeKey = useHkdf
                    ? Hkdf.derive(masterKey, Constants.HKDF_INFO_EME_NAMES, Constants.KEY_LEN)
                    : Arrays.copyOf(masterKey, masterKey.length);
            try {
                emeHelper = new Eme(new AesBlockCipher(emeKey));
            } finally {
                Keys.wipe(emeKey);
            }
            ContentGeometry contentGeometry = config.contentGeometry();
            NameTransform nameTransformHelper = new NameTransform(emeHelper, config.longNames(),
                    config.longNameMax(), config.raw64(), deterministic);

            this.store = store;
            this.rootName = root;
            this.config = config;
            this.masterKey = masterKey;
            this.ownsStore = ownsStore;
            this.readOnly = readOnly;
            this.rootLock = rootLock;
            this.plaintextNames = plainNames;
            this.eme = emeHelper;
            this.contentGeometry = contentGeometry;
            this.nameManager = new NameManager(nameTransformHelper, plainNames, store);
            this.directoryManager = new DirectoryManager(store, root, plainNames, deterministic,
                    nameTransformHelper, contentGeometry, this::deriveContentEnc,
                    this.nameManager, readOnly);
            this.pathResolver = new PathResolver(store, root, plainNames,
                    this.nameManager, this.directoryManager);
            this.fileManager = new FileManager(store, contentGeometry, this::deriveContentEnc,
                    nameTransformHelper, plainNames, this.nameManager, this.directoryManager,
                    this.pathResolver);
            this.fileManager.setSyncPolicy(syncPolicy);
            this.directoryManager.setFileManager(this.fileManager);
            constructed = true;
        } finally {
            if (!constructed) {
                // The constructor is aborting before ownership of the key
                // material transfers to the instance: wipe everything derived
                // here, including the master key.
                if (emeHelper != null) {
                    emeHelper.wipe();
                }
                Keys.wipe(masterKey);
            }
        }
    }

    /**
     * Opens an existing cipher store, unlocking the master key from
     * {@code password}.
     *
     * @param store    the ciphertext-side store
     * @param password the password to unlock the master key with, encoded as
     *                 UTF-8; read but neither retained nor wiped by this class
     * @return the opened filesystem
     * @throws IOException if the config is missing, the password is wrong or the filesystem is corrupt
     * @throws NullPointerException if {@code store} or {@code password} is {@code null}
     */
    public static GocryptFs open(CipherStore store, char[] password) throws IOException {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(password, "password");
        return open(store, password, false, false);
    }

    /**
     * Opens an existing cipher store, optionally read-only.
     *
     * <p>A read-only filesystem takes no writer lock and never writes to the
     * cipher directory. Mutating operations fail with an {@link IOException}.
     * Use this mode for media that cannot be written and for readers that must
     * coexist with a writable instance or mount.</p>
     *
     * @param store    the ciphertext-side store
     * @param password the password to unlock the master key with, encoded as
     *                 UTF-8; read but neither retained nor wiped by this class
     * @param readOnly whether to open without a writer lock and for reading only
     * @return the opened filesystem
     * @throws IOException if the config is missing, the password is wrong or the filesystem is corrupt
     * @throws NullPointerException if {@code store} or {@code password} is {@code null}
     */
    public static GocryptFs open(CipherStore store, char[] password, boolean readOnly)
            throws IOException {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(password, "password");
        return open(store, password, false, readOnly);
    }

    /**
     * Opens an existing cipher store read-only.
     *
     * @param store    the ciphertext-side store
     * @param password the password to unlock the master key with
     * @return the opened read-only filesystem
     * @throws IOException if the config is missing, the password is wrong or the filesystem is corrupt
     * @throws NullPointerException if {@code store} or {@code password} is {@code null}
     */
    public static GocryptFs openReadOnly(CipherStore store, char[] password) throws IOException {
        return open(store, password, true);
    }

    /**
     * Opens an existing cipher store with an explicit sync policy.
     *
     * @param store      the ciphertext-side store
     * @param password   the password to unlock the master key with
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException if the config is missing, the password is wrong or the filesystem is corrupt
     * @throws NullPointerException if {@code store}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs open(CipherStore store, char[] password, SyncPolicy syncPolicy)
            throws IOException {
        return open(store, password, false, syncPolicy);
    }

    /**
     * Opens an existing cipher store with an explicit sync policy.
     *
     * @param store      the ciphertext-side store
     * @param password   the password to unlock the master key with
     * @param readOnly   whether to open without a writer lock and for reading only
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException if the config is missing, the password is wrong or the filesystem is corrupt
     * @throws NullPointerException if {@code store}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs open(CipherStore store, char[] password, boolean readOnly,
                                 SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        return open(store, password, readOnly).withSyncPolicy(syncPolicy);
    }

    /**
     * Opens an existing cipher store with an explicit sync policy.
     *
     * @param store      the ciphertext-side store
     * @param password   the password to unlock the master key with
     * @param syncPolicy when buffered writes are flushed to storage
     * @param readOnly   whether to open without a writer lock and for reading only
     * @return the opened filesystem
     * @throws IOException if the config is missing, the password is wrong or the filesystem is corrupt
     * @throws NullPointerException if {@code store}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs open(CipherStore store, char[] password, SyncPolicy syncPolicy,
                                 boolean readOnly) throws IOException {
        return open(store, password, readOnly, syncPolicy);
    }

    /**
     * Opens an existing cipher store read-only with an explicit sync policy.
     *
     * @param store      the ciphertext-side store
     * @param password   the password to unlock the master key with
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened read-only filesystem
     * @throws IOException if the config is missing, the password is wrong or the filesystem is corrupt
     * @throws NullPointerException if {@code store}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs openReadOnly(CipherStore store, char[] password,
                                         SyncPolicy syncPolicy) throws IOException {
        return open(store, password, true, syncPolicy);
    }

    /**
     * Opens an existing cipher store, unlocking the master key from
     * {@code password}, recording whether the returned instance owns
     * {@code store}.
     */
    private static GocryptFs open(CipherStore store, char[] password, boolean ownsStore,
                                  boolean readOnly) throws IOException {
        CipherRootLock rootLock = readOnly ? null : CipherRootLock.acquire(store);
        boolean ok = false;
        try {
            ConfigFile config = ConfigFile.load(store);
            byte[] masterKey = config.decryptMasterKey(password);
            GocryptFs fs = new GocryptFs(store, config, masterKey, ownsStore, readOnly, rootLock);
            ok = true;
            return fs;
        } finally {
            if (!ok && rootLock != null) {
                closeQuietly(rootLock);
            }
        }
    }

    /**
     * Opens an existing cipher store using the raw 32-byte master key.
     *
     * @param store     the ciphertext-side store
     * @param masterKey the 32-byte master key; cloned, so the caller's array is
     *                  neither retained nor wiped by this class
     * @return the opened filesystem
     * @throws IOException if the config is missing or the filesystem is corrupt
     * @throws NullPointerException if {@code store} or {@code masterKey} is {@code null}
     * @throws IllegalArgumentException if {@code masterKey} is not 32 bytes long
     */
    public static GocryptFs open(CipherStore store, byte[] masterKey) throws IOException {
        return open(store, masterKey, false);
    }

    /**
     * Opens an existing cipher store using the raw 32-byte master key,
     * optionally read-only.
     *
     * @param store     the ciphertext-side store
     * @param masterKey the 32-byte master key; cloned, so the caller's array is
     *                  neither retained nor wiped by this class
     * @param readOnly  whether to open without a writer lock and for reading only
     * @return the opened filesystem
     * @throws IOException if the config is missing or the filesystem is corrupt
     * @throws NullPointerException if {@code store} or {@code masterKey} is {@code null}
     * @throws IllegalArgumentException if {@code masterKey} is not 32 bytes long
     */
    public static GocryptFs open(CipherStore store, byte[] masterKey, boolean readOnly)
            throws IOException {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(masterKey, "masterKey");
        if (masterKey.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("master key must be "
                    + Constants.KEY_LEN + " bytes");
        }
        return openMasterKey(store, masterKey, false, readOnly);
    }

    /**
     * Opens an existing cipher store using the raw 32-byte master key,
     * read-only.
     *
     * @param store     the ciphertext-side store
     * @param masterKey the 32-byte master key
     * @return the opened read-only filesystem
     * @throws IOException if the config is missing or the filesystem is corrupt
     * @throws NullPointerException if {@code store} or {@code masterKey} is {@code null}
     * @throws IllegalArgumentException if {@code masterKey} is not 32 bytes long
     */
    public static GocryptFs openReadOnly(CipherStore store, byte[] masterKey) throws IOException {
        return open(store, masterKey, true);
    }

    /**
     * Opens an existing cipher store using the raw master key with an explicit
     * sync policy.
     *
     * @param store      the ciphertext-side store
     * @param masterKey  the 32-byte master key
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException if the config is missing or the filesystem is corrupt
     * @throws NullPointerException if {@code store}, {@code masterKey} or {@code syncPolicy} is {@code null}
     * @throws IllegalArgumentException if {@code masterKey} is not 32 bytes long
     */
    public static GocryptFs open(CipherStore store, byte[] masterKey, SyncPolicy syncPolicy)
            throws IOException {
        return open(store, masterKey, false, syncPolicy);
    }

    /**
     * Opens an existing cipher store using the raw master key with an explicit
     * sync policy.
     *
     * @param store      the ciphertext-side store
     * @param masterKey  the 32-byte master key
     * @param readOnly   whether to open without a writer lock and for reading only
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException if the config is missing or the filesystem is corrupt
     * @throws NullPointerException if {@code store}, {@code masterKey} or {@code syncPolicy} is {@code null}
     * @throws IllegalArgumentException if {@code masterKey} is not 32 bytes long
     */
    public static GocryptFs open(CipherStore store, byte[] masterKey, boolean readOnly,
                                 SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        return open(store, masterKey, readOnly).withSyncPolicy(syncPolicy);
    }

    /**
     * Opens an existing cipher store using the raw master key with an explicit
     * sync policy.
     *
     * @param store      the ciphertext-side store
     * @param masterKey  the 32-byte master key
     * @param syncPolicy when buffered writes are flushed to storage
     * @param readOnly   whether to open without a writer lock and for reading only
     * @return the opened filesystem
     * @throws IOException if the config is missing or the filesystem is corrupt
     * @throws NullPointerException if {@code store}, {@code masterKey} or {@code syncPolicy} is {@code null}
     * @throws IllegalArgumentException if {@code masterKey} is not 32 bytes long
     */
    public static GocryptFs open(CipherStore store, byte[] masterKey, SyncPolicy syncPolicy,
                                 boolean readOnly) throws IOException {
        return open(store, masterKey, readOnly, syncPolicy);
    }

    /**
     * Opens an existing cipher store read-only using the raw master key with an
     * explicit sync policy.
     *
     * @param store      the ciphertext-side store
     * @param masterKey  the 32-byte master key
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened read-only filesystem
     * @throws IOException if the config is missing or the filesystem is corrupt
     * @throws NullPointerException if {@code store}, {@code masterKey} or {@code syncPolicy} is {@code null}
     * @throws IllegalArgumentException if {@code masterKey} is not 32 bytes long
     */
    public static GocryptFs openReadOnly(CipherStore store, byte[] masterKey,
                                         SyncPolicy syncPolicy) throws IOException {
        return open(store, masterKey, true, syncPolicy);
    }

    private static GocryptFs openMasterKey(CipherStore store, byte[] masterKey,
                                           boolean ownsStore, boolean readOnly)
            throws IOException {
        CipherRootLock rootLock = readOnly ? null : CipherRootLock.acquire(store);
        boolean ok = false;
        try {
            ConfigFile config = ConfigFile.load(store);
            GocryptFs fs = new GocryptFs(store, config, masterKey.clone(), ownsStore,
                    readOnly, rootLock);
            ok = true;
            return fs;
        } finally {
            if (!ok && rootLock != null) {
                closeQuietly(rootLock);
            }
        }
    }

    /**
     * Opens an existing FIDO2-protected cipher store.
     *
     * @param store the ciphertext-side store
     * @param token the FIDO2 token implementation to unlock the master key with
     * @return the opened filesystem
     * @throws IOException if the config is missing, not FIDO2-protected, or the token fails
     * @throws NullPointerException if {@code store} or {@code token} is {@code null}
     */
    public static GocryptFs open(CipherStore store, Fido2Token token) throws IOException {
        return open(store, token, false);
    }

    /**
     * Opens an existing FIDO2-protected cipher store, optionally read-only.
     *
     * @param store    the ciphertext-side store
     * @param token    the FIDO2 token implementation to unlock the master key with
     * @param readOnly whether to open without a writer lock and for reading only
     * @return the opened filesystem
     * @throws IOException if the config is missing, not FIDO2-protected, or the token fails
     * @throws NullPointerException if {@code store} or {@code token} is {@code null}
     */
    public static GocryptFs open(CipherStore store, Fido2Token token, boolean readOnly)
            throws IOException {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(token, "token");
        return openFido2(store, token, false, readOnly);
    }

    /**
     * Opens an existing FIDO2-protected cipher store read-only.
     *
     * @param store the ciphertext-side store
     * @param token the FIDO2 token implementation to unlock the master key with
     * @return the opened read-only filesystem
     * @throws IOException if the config is missing, not FIDO2-protected, or the token fails
     * @throws NullPointerException if {@code store} or {@code token} is {@code null}
     */
    public static GocryptFs openReadOnly(CipherStore store, Fido2Token token) throws IOException {
        return open(store, token, true);
    }

    private static GocryptFs openFido2(CipherStore store, Fido2Token token,
                                       boolean ownsStore, boolean readOnly) throws IOException {
        CipherRootLock rootLock = readOnly ? null : CipherRootLock.acquire(store);
        boolean ok = false;
        try {
            ConfigFile config = ConfigFile.load(store);
            Fido2Params params = config.fido2();
            if (!config.isFeatureFlagSet(Constants.FLAG_FIDO2) || params == null) {
                throw new IOException("filesystem is not protected by a FIDO2 token");
            }
            byte[] credentialId = params.credentialId();
            byte[] hmacSalt = params.hmacSalt();
            if (credentialId == null || hmacSalt == null) {
                throw new IOException("FIDO2 parameters are incomplete");
            }
            List<String> assertOptions = params.assertOptions() == null
                    ? Collections.<String>emptyList()
                    : params.assertOptions();
            byte[] secret = token.hmacSecret(credentialId, hmacSalt, assertOptions);
            try {
                checkFido2Secret(secret);
                byte[] masterKey = config.decryptMasterKey(secret);
                GocryptFs fs = new GocryptFs(store, config, masterKey, ownsStore, readOnly,
                        rootLock);
                ok = true;
                return fs;
            } catch (IOException e) {
                if (e.getCause() instanceof GeneralSecurityException) {
                    throw new IOException("FIDO2 HMAC secret did not unlock the master key "
                            + "(wrong security key or credential?)", e);
                }
                throw e;
            } finally {
                Keys.wipe(secret);
            }
        } finally {
            if (!ok && rootLock != null) {
                closeQuietly(rootLock);
            }
        }
    }

    /**
     * Opens a cipher store identified by a URI, dispatching on the URI scheme to
     * a registered {@link de.sfuhrm.gocryptfs4j.store.CipherStoreProvider}.
     *
     * @param uri      the URI identifying the store
     * @param env      backend-specific options, or {@code null} for defaults
     * @param password the password to unlock the master key with
     * @return the opened filesystem
     * @throws IOException if no provider handles the scheme, or opening fails
     * @throws NullPointerException if {@code uri} or {@code password} is {@code null}
     */
    public static GocryptFs open(URI uri, Map<String, ?> env, char[] password) throws IOException {
        return open(uri, env, password, false);
    }

    /**
     * Opens a cipher store identified by a URI, optionally read-only.
     *
     * @param uri      the URI identifying the store
     * @param env      backend-specific options, or {@code null} for defaults
     * @param password the password to unlock the master key with
     * @param readOnly whether to open without a writer lock and for reading only
     * @return the opened filesystem
     * @throws IOException if no provider handles the scheme, or opening fails
     * @throws NullPointerException if {@code uri} or {@code password} is {@code null}
     */
    public static GocryptFs open(URI uri, Map<String, ?> env, char[] password, boolean readOnly)
            throws IOException {
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(password, "password");
        CipherStore store = CipherStores.newStore(uri, env);
        boolean ok = false;
        try {
            GocryptFs fs = open(store, password, true, readOnly);
            ok = true;
            return fs;
        } finally {
            if (!ok) {
                store.close();
            }
        }
    }

    /**
     * Opens a cipher store identified by a URI read-only.
     *
     * @param uri      the URI identifying the store
     * @param env      backend-specific options, or {@code null} for defaults
     * @param password the password to unlock the master key with
     * @return the opened read-only filesystem
     * @throws IOException if no provider handles the scheme, or opening fails
     * @throws NullPointerException if {@code uri} or {@code password} is {@code null}
     */
    public static GocryptFs openReadOnly(URI uri, Map<String, ?> env, char[] password)
            throws IOException {
        return open(uri, env, password, true);
    }

    /**
     * Opens a cipher store identified by a URI with an explicit sync policy.
     *
     * @param uri        the URI identifying the store
     * @param env        backend-specific options, or {@code null} for defaults
     * @param password   the password to unlock the master key with
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException if no provider handles the scheme, or opening fails
     * @throws NullPointerException if {@code uri}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs open(URI uri, Map<String, ?> env, char[] password,
                                 SyncPolicy syncPolicy) throws IOException {
        return open(uri, env, password, false, syncPolicy);
    }

    /**
     * Opens a cipher store identified by a URI with an explicit sync policy.
     *
     * @param uri        the URI identifying the store
     * @param env        backend-specific options, or {@code null} for defaults
     * @param password   the password to unlock the master key with
     * @param readOnly   whether to open without a writer lock and for reading only
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException if no provider handles the scheme, or opening fails
     * @throws NullPointerException if {@code uri}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs open(URI uri, Map<String, ?> env, char[] password, boolean readOnly,
                                 SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        return open(uri, env, password, readOnly).withSyncPolicy(syncPolicy);
    }

    /**
     * Opens a cipher store identified by a URI read-only with an explicit sync
     * policy.
     *
     * @param uri        the URI identifying the store
     * @param env        backend-specific options, or {@code null} for defaults
     * @param password   the password to unlock the master key with
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened read-only filesystem
     * @throws IOException if no provider handles the scheme, or opening fails
     * @throws NullPointerException if {@code uri}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs openReadOnly(URI uri, Map<String, ?> env, char[] password,
                                         SyncPolicy syncPolicy) throws IOException {
        return open(uri, env, password, true, syncPolicy);
    }

    /**
     * Creates a new filesystem in a cipher store identified by a URI.
     *
     * @param uri      the URI identifying the store
     * @param env      backend-specific options, or {@code null} for defaults
     * @param password the password to protect the master key with
     * @return the opened filesystem
     * @throws IOException if no provider handles the scheme, or creation fails
     */
    public static GocryptFs create(URI uri, Map<String, ?> env, char[] password) throws IOException {
        return create(uri, env, password, false, ContentCipherType.AES_GCM);
    }

    /**
     * Creates a new filesystem in a cipher store identified by a URI, optionally
     * with plaintext names and a custom content cipher.
     *
     * @param uri            the URI identifying the store
     * @param env            backend-specific options, or {@code null} for defaults
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @param cipherType     the content-encryption cipher
     * @return the opened filesystem
     * @throws IOException if no provider handles the scheme, or creation fails
     * @throws NullPointerException if {@code uri}, {@code password} or {@code cipherType} is {@code null}
     */
    public static GocryptFs create(URI uri, Map<String, ?> env, char[] password,
                                   boolean plaintextNames, ContentCipherType cipherType)
            throws IOException {
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(cipherType, "cipherType");
        CipherStore store = CipherStores.newStore(uri, env);
        boolean ok = false;
        try {
            GocryptFs fs = create(store, password, plaintextNames, cipherType, true);
            ok = true;
            return fs;
        } finally {
            if (!ok) {
                store.close();
            }
        }
    }

    /**
     * Creates a new filesystem in a cipher store identified by a URI with an
     * explicit sync policy.
     *
     * @param uri        the URI identifying the store
     * @param env        backend-specific options, or {@code null} for defaults
     * @param password   the password to protect the master key with
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException if no provider handles the scheme, or creation fails
     * @throws NullPointerException if {@code uri}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs create(URI uri, Map<String, ?> env, char[] password,
                                   SyncPolicy syncPolicy) throws IOException {
        return create(uri, env, password, false, ContentCipherType.AES_GCM, syncPolicy);
    }

    /**
     * Creates a new filesystem in a cipher store identified by a URI with an
     * explicit sync policy.
     *
     * @param uri            the URI identifying the store
     * @param env            backend-specific options, or {@code null} for defaults
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @param cipherType     the content-encryption cipher
     * @param syncPolicy     when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException if no provider handles the scheme, or creation fails
     * @throws NullPointerException if {@code uri}, {@code password}, {@code cipherType} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs create(URI uri, Map<String, ?> env, char[] password,
                                   boolean plaintextNames, ContentCipherType cipherType,
                                   SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        return create(uri, env, password, plaintextNames, cipherType).withSyncPolicy(syncPolicy);
    }

    /**
     * Creates a new filesystem in the given cipher store (whose root must be
     * empty).
     *
     * @param store    the ciphertext-side store, whose root must be empty
     * @param password the password to protect the master key with
     * @return the opened filesystem
     * @throws IOException on storage errors
     */
    public static GocryptFs create(CipherStore store, char[] password) throws IOException {
        return create(store, password, false, ContentCipherType.AES_GCM);
    }

    /**
     * Creates a new filesystem in the given cipher store, optionally with
     * plaintext (unencrypted) names.
     *
     * @param store          the ciphertext-side store, whose root must be empty
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @return the opened filesystem
     * @throws IOException on storage errors
     */
    public static GocryptFs create(CipherStore store, char[] password, boolean plaintextNames)
            throws IOException {
        return create(store, password, plaintextNames, ContentCipherType.AES_GCM);
    }

    /**
     * Creates a new filesystem in the given cipher store (whose root must be
     * empty), optionally with plaintext names and a custom content cipher.
     *
     * @param store          the ciphertext-side store, whose root must be empty
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @param cipherType     the content-encryption cipher
     * @return the opened filesystem
     * @throws IOException on storage errors
     * @throws NullPointerException if {@code store}, {@code password} or {@code cipherType} is {@code null}
     */
    public static GocryptFs create(CipherStore store, char[] password, boolean plaintextNames,
                                   ContentCipherType cipherType) throws IOException {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(cipherType, "cipherType");
        return create(store, password, plaintextNames, cipherType, false);
    }

    /**
     * Creates a new filesystem with an explicit sync policy.
     *
     * @param store      the ciphertext-side store, whose root must be empty
     * @param password   the password to protect the master key with
     * @param syncPolicy when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException on storage errors
     * @throws NullPointerException if {@code store}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs create(CipherStore store, char[] password, SyncPolicy syncPolicy)
            throws IOException {
        return create(store, password, false, ContentCipherType.AES_GCM, syncPolicy);
    }

    /**
     * Creates a new filesystem with an explicit sync policy.
     *
     * @param store          the ciphertext-side store, whose root must be empty
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @param syncPolicy     when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException on storage errors
     * @throws NullPointerException if {@code store}, {@code password} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs create(CipherStore store, char[] password, boolean plaintextNames,
                                   SyncPolicy syncPolicy) throws IOException {
        return create(store, password, plaintextNames, ContentCipherType.AES_GCM, syncPolicy);
    }

    /**
     * Creates a new filesystem with an explicit sync policy.
     *
     * @param store          the ciphertext-side store, whose root must be empty
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @param cipherType     the content-encryption cipher
     * @param syncPolicy     when buffered writes are flushed to storage
     * @return the opened filesystem
     * @throws IOException on storage errors
     * @throws NullPointerException if {@code store}, {@code password}, {@code cipherType} or {@code syncPolicy} is {@code null}
     */
    public static GocryptFs create(CipherStore store, char[] password, boolean plaintextNames,
                                   ContentCipherType cipherType, SyncPolicy syncPolicy)
            throws IOException {
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        return create(store, password, plaintextNames, cipherType).withSyncPolicy(syncPolicy);
    }

    /**
     * Creates a new filesystem, recording whether the returned instance owns
     * {@code store} and must close it on {@link #close()}.
     */
    private static GocryptFs create(CipherStore store, char[] password, boolean plaintextNames,
                                    ContentCipherType cipherType, boolean ownsStore)
            throws IOException {
        CipherRootLock rootLock = CipherRootLock.acquire(store);
        byte[] masterKey = null;
        boolean ok = false;
        try {
            if (!isCreateRootEmpty(store, plaintextNames)) {
                throw new IOException("cipher dir is not empty: " + store.root());
            }
            masterKey = Keys.randomBytes(Constants.KEY_LEN);
            ConfigFile config = ConfigFile.create(masterKey, password, plaintextNames, cipherType);
            byte[] configBytes = config.toBytes();
            String configName = PathResolver.join(store.root(), Constants.CONF_DEFAULT_NAME);
            GocryptFs fs = new GocryptFs(store, config, masterKey, ownsStore, false, rootLock);
            boolean configCreated = false;
            boolean dirIVCreated = false;
            try {
                // Write the diriv first and the config last: the config is the
                // commit marker, so a crash before it leaves only an orphan
                // diriv that a later create can replace.
                if (!plaintextNames) {
                    dirIVCreated = writeRootDirIVForCreate(store, fs.directoryManager,
                            configName);
                }
                store.writeConfig(configName, configBytes, false);
                configCreated = true;
                ok = true;
                return fs;
            } catch (FileAlreadyExistsException e) {
                // Another creator won the config race. Never remove its files.
                fs.wipeSecrets();
                throw e;
            } catch (Throwable t) {
                fs.wipeSecrets();
                cleanupCreate(store, configName, configCreated, dirIVCreated);
                throw t;
            }
        } finally {
            if (!ok) {
                if (masterKey != null) {
                    Keys.wipe(masterKey);
                }
                closeQuietly(rootLock);
            }
        }
    }

    /**
     * Returns whether a cipher store's root is empty enough to create a new
     * filesystem in.
     *
     * <p>A config file always makes the root non-empty because it is the commit
     * marker of a completed create. An orphan {@code gocryptfs.diriv} is
     * ignored in encrypted-name mode: it can only be left behind by a create
     * that crashed before writing the config, and the new create replaces it.
     * Internal files (atomic-write temporaries and the root lock file) are also
     * ignored: they are created by gocryptfs itself and are not user entries.
     * In plaintext-names mode the whole {@code gocryptfs.} prefix is reserved
     * at the root, so a leftover backup such as {@code gocryptfs.conf.bak} does
     * not block creating a fresh filesystem. The config is also checked
     * directly, so a stale (eventually consistent) directory listing cannot
     * hide a committed filesystem and cause its diriv to be replaced.</p>
     *
     * @param store          the ciphertext-side store
     * @param plaintextNames whether the new filesystem stores names unencrypted
     * @return {@code true} if the root can be used for a new filesystem
     * @throws IOException on storage errors
     */
    private static boolean isCreateRootEmpty(CipherStore store, boolean plaintextNames)
            throws IOException {
        String root = store.root();
        if (exists(store, PathResolver.join(root, Constants.CONF_DEFAULT_NAME))) {
            return false;
        }
        for (CipherNode node : store.list(root)) {
            String name = node.name();
            if (!plaintextNames && name.equals(Constants.DIR_IV_FILENAME)) {
                continue;
            }
            if (name.startsWith(Constants.INTERNAL_NAME_PREFIX)) {
                continue;
            }
            if (plaintextNames && name.startsWith(Constants.RESERVED_ROOT_PREFIX)) {
                continue;
            }
            return false;
        }
        return true;
    }

    /**
     * Writes the root diriv for a new filesystem with create-new semantics.
     *
     * <p>An already existing diriv may be an orphan left by a create that
     * crashed before writing the config, so it is replaced. Before that, the
     * absence of a config is re-checked immediately before the diriv is
     * touched, and the directory is verified to contain no other entries. A
     * diriv that belongs to a concurrent creator is therefore not overwritten
     * once that creator has committed its config.</p>
     *
     * @param store            the ciphertext-side store
     * @param directoryManager the directory manager that writes the diriv
     * @param configName       the ciphertext path of the config file
     * @return {@code true} if this call created the diriv file, {@code false}
     *         if an existing orphan was replaced
     * @throws IOException on storage errors or if a config or user entry
     *                     already exists
     */
    private static boolean writeRootDirIVForCreate(CipherStore store,
                                                   DirectoryManager directoryManager,
                                                   String configName) throws IOException {
        // Re-check the commit marker immediately before touching the diriv.
        if (exists(store, configName)) {
            throw new IOException("cipher dir is not empty: " + store.root());
        }
        try {
            directoryManager.writeDirIV(store.root(), false);
            return true;
        } catch (FileAlreadyExistsException e) {
            // Only replace the diriv if it is a verified orphan: no config and
            // no other user entries. The check includes the config again, so a
            // concurrent creator that has committed in the meantime wins.
            if (!isCreateRootEmpty(store, false)) {
                throw new IOException("cipher dir is not empty: " + store.root(), e);
            }
            directoryManager.writeDirIV(store.root(), true);
            return false;
        }
    }

    /**
     * Creates a new FIDO2-protected filesystem in the given cipher store, whose
     * root must be empty. Uses AES-256-GCM and encrypted names.
     *
     * @param store the ciphertext-side store, whose root must be empty
     * @param token the FIDO2 token implementation to protect the master key with
     * @return the opened filesystem
     * @throws IOException on storage errors or if the token interaction fails
     * @throws NullPointerException if {@code store} or {@code token} is {@code null}
     */
    public static GocryptFs create(CipherStore store, Fido2Token token) throws IOException {
        return create(store, token, null, false, ContentCipherType.AES_GCM,
                Collections.<String>emptyList());
    }

    /**
     * Creates a new FIDO2-protected filesystem in the given cipher store,
     * optionally with plaintext names and a custom content cipher.
     *
     * @param store          the ciphertext-side store, whose root must be empty
     * @param token          the FIDO2 token implementation to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @param cipherType     the content-encryption cipher
     * @return the opened filesystem
     * @throws IOException on storage errors or if the token interaction fails
     * @throws NullPointerException if {@code store}, {@code token} or {@code cipherType} is {@code null}
     */
    public static GocryptFs create(CipherStore store, Fido2Token token, boolean plaintextNames,
                                   ContentCipherType cipherType) throws IOException {
        return create(store, token, null, plaintextNames, cipherType,
                Collections.<String>emptyList());
    }

    /**
     * Creates a new FIDO2-protected filesystem in the given cipher store.
     *
     * @param store          the ciphertext-side store, whose root must be empty
     * @param token          the FIDO2 token implementation to protect the master key with
     * @param userName       the user name to register the credential with, or
     *                       {@code null} to use the base name of the store root
     * @param plaintextNames whether to store file names unencrypted
     * @param cipherType     the content-encryption cipher
     * @param assertOptions  options to pass to the token assertion, or {@code null}
     * @return the opened filesystem
     * @throws IOException on storage errors or if the token interaction fails
     * @throws NullPointerException if {@code store}, {@code token} or {@code cipherType} is {@code null}
     */
    public static GocryptFs create(CipherStore store, Fido2Token token, @Nullable String userName,
                                   boolean plaintextNames, ContentCipherType cipherType,
                                   @Nullable List<String> assertOptions) throws IOException {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(cipherType, "cipherType");
        CipherRootLock rootLock = CipherRootLock.acquire(store);
        boolean ok = false;
        try {
            if (!isCreateRootEmpty(store, plaintextNames)) {
                throw new IOException("cipher dir is not empty: " + store.root());
            }
            List<String> options = assertOptions == null
                    ? Collections.<String>emptyList()
                    : new ArrayList<>(assertOptions);
            String name = userName != null ? userName : PathResolver.baseName(store.root());

            byte[] credentialId = token.registerCredential(name);
            byte[] hmacSalt = Keys.randomBytes(Fido2Params.HMAC_SALT_LEN);
            byte[] secret = token.hmacSecret(credentialId, hmacSalt, options);
            try {
                checkFido2Secret(secret);
                byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
                boolean created = false;
                try {
                    ConfigFile config = ConfigFile.create(masterKey, secret, plaintextNames,
                            cipherType, new Fido2Params(credentialId, hmacSalt, options));
                    byte[] configBytes = config.toBytes();
                    String configName = PathResolver.join(store.root(),
                            Constants.CONF_DEFAULT_NAME);
                    GocryptFs fs = new GocryptFs(store, config, masterKey, false, false,
                            rootLock);
                    boolean configCreated = false;
                    boolean dirIVCreated = false;
                    try {
                        // Write the diriv first and the config last: the config
                        // is the commit marker, so a crash before it leaves only
                        // an orphan diriv that a later create can replace.
                        if (!plaintextNames) {
                            dirIVCreated = writeRootDirIVForCreate(store,
                                    fs.directoryManager, configName);
                        }
                        store.writeConfig(configName, configBytes, false);
                        configCreated = true;
                        created = true;
                        ok = true;
                        return fs;
                    } catch (FileAlreadyExistsException e) {
                        // Another creator won the config race. Never remove its files.
                        fs.wipeSecrets();
                        throw e;
                    } catch (Throwable t) {
                        fs.wipeSecrets();
                        cleanupCreate(store, configName, configCreated, dirIVCreated);
                        throw t;
                    }
                } finally {
                    if (!created) {
                        Keys.wipe(masterKey);
                    }
                }
            } finally {
                Keys.wipe(secret);
            }
        } finally {
            if (!ok) {
                closeQuietly(rootLock);
            }
        }
    }

    /**
     * Validates a FIDO2 {@code hmac-secret} returned by a {@link Fido2Token}.
     *
     * <p>A secret shorter than {@link Constants#FIDO2_MIN_SECRET_LEN} bytes or an
     * all-zero secret is rejected. This is enforced here, in the core, rather
     * than relying on individual token implementations, so that a buggy or
     * failing custom {@link Fido2Token} cannot create an effectively unprotected
     * filesystem.</p>
     *
     * @param secret the secret returned by the token
     * @throws IOException if the secret is {@code null}, too short or all-zero
     */
    private static void checkFido2Secret(byte[] secret) throws IOException {
        if (secret == null) {
            throw new IOException("FIDO2 HMAC secret is null");
        }
        if (secret.length < Constants.FIDO2_MIN_SECRET_LEN) {
            throw new IOException("FIDO2 HMAC secret too short ("
                    + secret.length + " bytes, want at least "
                    + Constants.FIDO2_MIN_SECRET_LEN + ")");
        }
        if (isAllZero(secret)) {
            throw new IOException("FIDO2 HMAC secret is all zero");
        }
    }

    /**
     * Returns whether the whole array is all zero.
     *
     * @param data the array
     * @return {@code true} if every byte is zero
     */
    private static boolean isAllZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns whether file names are stored unencrypted.
     *
     * @return true if file names are stored unencrypted
     */
    public boolean plaintextNames() {
        ensureOpen();
        return plaintextNames;
    }

    /**
     * Returns whether this filesystem was opened read-only.
     *
     * @return {@code true} if this filesystem is read-only
     */
    public boolean isReadOnly() {
        ensureOpen();
        return readOnly;
    }

    /**
     * Returns whether this filesystem was opened read-only.
     *
     * @return {@code true} if this filesystem is read-only
     */
    public boolean readOnly() {
        return isReadOnly();
    }

    /**
     * Returns the read lock guarding read operations (listing, stat, reads and
     * content writes to existing files).
     *
     * @return the read lock
     */
    public Lock readLock() {
        ensureOpen();
        return lock.readLock();
    }

    /**
     * Returns the write lock guarding namespace-mutating operations (create,
     * delete, rename, mkdir and open).
     *
     * @return the write lock
     */
    public Lock writeLock() {
        ensureOpen();
        return lock.writeLock();
    }

    /**
     * Returns a copy of this filesystem's 32-byte master key for recovery.
     *
     * <p><strong>Security warning:</strong> the master key is the only secret
     * needed to decrypt every file in the cipher directory. It cannot be
     * recovered if lost, but it must never be logged, committed, sent over an
     * untrusted channel or stored next to the ciphertext. Anyone who obtains
     * it can read and modify the filesystem even without the password. Keep it
     * in a secure offline location, separate from both the cipher directory
     * and the {@code gocryptfs.conf} file.</p>
     *
     * <p>The returned array is a fresh copy owned by the caller and remains
     * valid after this filesystem is closed. It is mutable so the caller can
     * (and should) wipe it with {@link java.util.Arrays#fill(byte[], byte)}
     * once it is no longer needed; this class does not retain or wipe it.</p>
     *
     * @return a newly allocated copy of the 32-byte master key
     * @throws IllegalStateException if this filesystem has been closed
     */
    public byte[] exportMasterKey() {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            return masterKey.clone();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Formats a master key like gocryptfs's master-key reminder: lowercase hex
     * split into groups of eight hexadecimal digits separated by dashes.
     *
     * <p>The result can be passed directly to {@code gocryptfs -masterkey}, and
     * {@code gocryptfs} ignores the dashes when parsing it.</p>
     *
     * @param masterKey the master key bytes
     * @return the dash-separated hexadecimal representation
     * @throws NullPointerException if {@code masterKey} is {@code null}
     */
    public static String formatMasterKey(byte[] masterKey) {
        Objects.requireNonNull(masterKey, "masterKey");
        StringBuilder hex = new StringBuilder(masterKey.length * 2);
        for (byte b : masterKey) {
            hex.append(Character.forDigit((b >>> 4) & 0x0f, 16));
            hex.append(Character.forDigit(b & 0x0f, 16));
        }
        StringBuilder out = new StringBuilder(hex.length() + hex.length() / 8);
        for (int i = 0; i < hex.length(); i += 8) {
            if (i > 0) {
                out.append('-');
            }
            out.append(hex, i, Math.min(i + 8, hex.length()));
        }
        return out.toString();
    }

    /**
     * Changes the password protecting this filesystem's master key and writes
     * the updated {@code gocryptfs.conf} atomically.
     *
     * <p>This is the equivalent of gocryptfs's {@code -passwd}. The master key
     * itself is unchanged, so the ciphertext of every existing file remains
     * valid; only the scrypt salt and the encrypted master-key blob are
     * rewritten. The scrypt cost is upgraded to at least the current default.
     * The supplied password is read but neither retained nor wiped by this
     * class, so the caller should clear it when it is no longer needed.</p>
     *
     * <p>No {@code gocryptfs.conf.bak} is written. A backup would keep the old
     * password working, which defeats a password change after the old password
     * leaked. Use {@link #changePassword(char[], boolean)} with
     * {@code keepBackup = true} only when the backup is needed to recover from
     * a mistyped new password, and delete it after verifying the new one.</p>
     *
     * @param password the new password, encoded as UTF-8; read but neither
     *                 retained nor wiped by this class
     * @throws IOException on filesystem errors, or if the config cannot be
     *                     written atomically
     * @throws NullPointerException if {@code password} is {@code null}
     * @throws IllegalStateException if this filesystem is protected by a FIDO2
     *                               token, whose key protection cannot be
     *                               changed to a password
     */
    public void changePassword(char[] password) throws IOException {
        changePassword(password, false);
    }

    /**
     * Changes the password protecting this filesystem's master key, optionally
     * keeping a backup of the old {@code gocryptfs.conf}.
     *
     * <p>When {@code keepBackup} is {@code true}, the previous config is
     * written to {@code gocryptfs.conf.bak} with mode {@code 0400} before the
     * new config replaces it. The backup is still protected by the old
     * password, so anyone who knows a leaked old password can still unlock the
     * master key through it. Delete the backup after verifying that the new
     * password works; never keep it when the password change was prompted by a
     * leak.</p>
     *
     * @param password   the new password, encoded as UTF-8; read but neither
     *                   retained nor wiped by this class
     * @param keepBackup whether to keep the old config as
     *                   {@code gocryptfs.conf.bak}
     * @throws IOException on filesystem errors, or if the config cannot be
     *                     written atomically
     * @throws NullPointerException if {@code password} is {@code null}
     * @throws IllegalStateException if this filesystem is protected by a FIDO2
     *                               token, whose key protection cannot be
     *                               changed to a password
     */
    public void changePassword(char[] password, boolean keepBackup) throws IOException {
        changePassword(password, keepBackup, 0);
    }

    /**
     * Changes the password protecting this filesystem's master key with an
     * explicit scrypt cost, without keeping a backup of the old config.
     *
     * <p>{@code scryptCost} is either a scrypt {@code logN} value (for example
     * {@code 16}) or an actual power-of-two {@code N} value. A value of
     * {@code 0} keeps the automatic upgrade to at least the current default.
     * See {@link #changePassword(char[], boolean)} for the backup warning.</p>
     *
     * @param password   the new password, encoded as UTF-8; read but neither
     *                   retained nor wiped by this class
     * @param scryptCost the scrypt {@code logN} or {@code N} value, or {@code 0}
     *                   to use the automatic upgrade
     * @throws IOException on filesystem errors, or if the config cannot be
     *                     written atomically
     * @throws NullPointerException if {@code password} is {@code null}
     * @throws IllegalArgumentException if {@code scryptCost} is invalid
     * @throws IllegalStateException if this filesystem is protected by a FIDO2
     *                               token, whose key protection cannot be
     *                               changed to a password
     */
    public void changePassword(char[] password, int scryptCost) throws IOException {
        changePassword(password, false, scryptCost);
    }

    /**
     * Changes the password protecting this filesystem's master key with an
     * explicit scrypt cost and optional backup.
     *
     * @param password   the new password, encoded as UTF-8; read but neither
     *                   retained nor wiped by this class
     * @param scryptCost the scrypt {@code logN} or {@code N} value, or {@code 0}
     *                   to use the automatic upgrade
     * @param keepBackup whether to keep the old config as
     *                   {@code gocryptfs.conf.bak}
     * @throws IOException on filesystem errors, or if the config cannot be
     *                     written atomically
     * @throws NullPointerException if {@code password} is {@code null}
     * @throws IllegalArgumentException if {@code scryptCost} is invalid
     * @throws IllegalStateException if this filesystem is protected by a FIDO2
     *                               token, whose key protection cannot be
     *                               changed to a password
     */
    public void changePassword(char[] password, int scryptCost, boolean keepBackup)
            throws IOException {
        changePassword(password, keepBackup, scryptCost);
    }

    /**
     * Changes the password protecting this filesystem's master key, with an
     * optional old-config backup and an explicit scrypt cost.
     *
     * @param password   the new password, encoded as UTF-8
     * @param keepBackup whether to write the old config to
     *                   {@code gocryptfs.conf.bak}
     * @param scryptCost the scrypt {@code logN} or {@code N} value, or {@code 0}
     *                   to use the automatic upgrade
     * @throws IOException on filesystem errors, or if the config cannot be
     *                     written atomically
     * @throws NullPointerException if {@code password} is {@code null}
     * @throws IllegalArgumentException if {@code scryptCost} is invalid
     * @throws IllegalStateException if this filesystem is protected by a FIDO2
     *                               token, whose key protection cannot be
     *                               changed to a password
     */
    public void changePassword(char[] password, boolean keepBackup, int scryptCost)
            throws IOException {
        Objects.requireNonNull(password, "password");
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            String configName = PathResolver.join(rootName, Constants.CONF_DEFAULT_NAME);
            // Compute the new config before touching the store. In particular,
            // a FIDO2 filesystem must fail here without leaving a stray .bak.
            ConfigFile updated = scryptCost == 0
                    ? config.reencryptMasterKeyCopy(masterKey, password)
                    : config.reencryptMasterKeyCopy(masterKey, password, scryptCost);
            if (keepBackup) {
                // The old config still unlocks with the old password. Write it
                // with the same 0400 permissions as gocryptfs.conf.
                byte[] previous = store.readSmall(configName, Constants.CONFIG_MAX_SIZE);
                store.writeConfig(configName + ".bak", previous, true);
            }
            store.writeConfig(configName, updated.toBytes(), true);
            config = updated;
        } finally {
            writeLock.unlock();
        }
    }

    // ------------------------------------------------------------------
    // Name mapping (delegated)
    // ------------------------------------------------------------------

    /**
     * Encrypts (and possibly hashes) a plaintext name using {@code dirIV}.
     *
     * @param plainName the plaintext name
     * @param dirIV     the 16-byte directory IV
     * @return the ciphertext name
     * @throws NullPointerException if {@code plainName} or {@code dirIV} is {@code null}
     */
    String cipherNameFor(String plainName, byte[] dirIV) throws IOException {
        ensureOpen();
        return nameManager.cipherNameFor(plainName, dirIV);
    }

    /**
     * Encrypts a plaintext name under {@code dirIV} without validation and
     * without long-name hashing. Used by tests to inject corrupt ciphertext
     * entries (for example a name containing a NUL byte) that the public API
     * refuses to create, so that listing robustness can be exercised.
     *
     * @param plainName the plaintext name
     * @param dirIV     the 16-byte directory IV
     * @return the full (unhashed) ciphertext name
     * @throws NullPointerException if {@code plainName} or {@code dirIV} is {@code null}
     */
    String encryptNameRaw(String plainName, byte[] dirIV) {
        ensureOpen();
        return nameManager.encryptName(plainName, dirIV);
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
        ensureOpen();
        return directoryManager.readDirIV(cipherDir);
    }

    // ------------------------------------------------------------------
    // Path resolution (delegated)
    // ------------------------------------------------------------------

    /**
     * Resolves a plaintext absolute path (for example {@code "/a/b.txt"}) to its
     * cipher path.
     *
     * @param plainPath the plaintext absolute path
     * @return the resolution result
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     * @throws IllegalArgumentException if the path contains a {@code ..} component
     *                                  or targets the reserved {@code gocryptfs.conf} control file
     */
    PathResolver.Resolved resolve(String plainPath) throws IOException {
        ensureOpen();
        return pathResolver.resolve(plainPath);
    }

    // ------------------------------------------------------------------
    // Listing
    // ------------------------------------------------------------------

    /**
     * Lists a plaintext directory path, returning entries sorted by name.
     *
     * <p>Entries that cannot be decrypted or resolved are silently skipped, as
     * in a gocryptfs mount. Use {@link #list(String, SkippedEntryListener)} to
     * observe them or {@link #list(String, boolean)} to fail instead.</p>
     *
     * @param plainDir the plaintext directory path
     * @return the directory entries sorted by plaintext name
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    public List<DirEntry> list(String plainDir) throws IOException {
        return list(plainDir, (SkippedEntryListener) null);
    }

    /**
     * Lists a plaintext directory path, optionally failing instead of skipping
     * corrupt entries.
     *
     * @param plainDir the plaintext directory path
     * @param strict   whether to fail with an {@link IOException} when an entry
     *                 cannot be decrypted or resolved
     * @return the directory entries sorted by plaintext name
     * @throws IOException on filesystem errors, or in strict mode when an entry
     *                     would have been skipped
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    public List<DirEntry> list(String plainDir, boolean strict) throws IOException {
        if (!strict) {
            return list(plainDir, (SkippedEntryListener) null);
        }
        return list(plainDir, (cipherName, reason) -> {
            throw new IOException("cannot list " + plainDir + ": skipped entry "
                    + cipherName + ": " + reason.getMessage(), reason);
        });
    }

    /**
     * Lists a plaintext directory path, failing instead of skipping corrupt
     * entries.
     *
     * <p>This is a convenience alias for {@code list(plainDir, true)}.</p>
     *
     * @param plainDir the plaintext directory path
     * @return the directory entries sorted by plaintext name
     * @throws IOException on filesystem errors or when an entry cannot be
     *                     decrypted or resolved
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    public List<DirEntry> listStrict(String plainDir) throws IOException {
        return list(plainDir, true);
    }

    /**
     * Lists a plaintext directory path, reporting entries that are skipped.
     *
     * <p>The listener is called for each corrupt entry; if it throws, the
     * listing is aborted with that exception. A {@code null} listener preserves
     * the default silent-skip behaviour.</p>
     *
     * @param plainDir the plaintext directory path
     * @param listener the callback for skipped entries, or {@code null}
     * @return the directory entries sorted by plaintext name
     * @throws IOException on filesystem errors, or when the listener aborts
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    public List<DirEntry> list(String plainDir,
                               @Nullable SkippedEntryListener listener) throws IOException {
        Objects.requireNonNull(plainDir, "plainDir");
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            PathResolver.Resolved r = pathResolver.resolve(plainDir);
            byte[] iv = directoryManager.readDirIV(r.cipherPath());
            List<DirEntry> entries = directoryManager.listCipherDir(r.cipherPath(), iv, listener);
            entries.sort(Comparator.comparing(DirEntry::plainName));
            return entries;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Captures a ciphertext-side snapshot of a plaintext directory for change
     * detection.
     *
     * <p>Unlike {@link #list(String)}, this does not decrypt every entry name.
     * It records the ciphertext names and metadata, and the returned snapshot's
     * {@link DirectorySnapshot#changesSince(DirectorySnapshot)} decrypts only
     * the names of entries that actually changed. This is intended for polling
     * watchers, which can remain cheap on large, mostly unchanged
     * directories.</p>
     *
     * @param plainDir the plaintext directory path
     * @return the snapshot of the directory
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    public DirectorySnapshot snapshotDirectory(String plainDir) throws IOException {
        Objects.requireNonNull(plainDir, "plainDir");
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            PathResolver.Resolved r = pathResolver.resolve(plainDir);
            return directoryManager.snapshotDirectory(r.cipherPath());
        } finally {
            readLock.unlock();
        }
    }

    // ------------------------------------------------------------------
    // Content access (delegated)
    // ------------------------------------------------------------------

    /**
     * Returns the plaintext attributes of a path (file, directory or symlink).
     *
     * @param plainPath the plaintext path
     * @return the directory entry
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    public DirEntry stat(String plainPath) throws IOException {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            return fileManager.stat(plainPath);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Opens a plaintext file for random access, sharing one backing cipher file
     * (with reference counting) across concurrently open handles on the same
     * file.
     *
     * @param plainFile the plaintext file path
     * @param writable  whether to open for writing
     * @return the opened cipher file handle
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    public SharedCipherFile openCipherFile(String plainFile, boolean writable) throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            if (writable) {
                ensureWritable();
            }
            return fileManager.openCipherFile(plainFile, writable);
        } finally {
            writeLock.unlock();
        }
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
    public SharedCipherFile openCipherFile(String plainFile, boolean writable,
                                           SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            if (writable) {
                ensureWritable();
            }
            return fileManager.openCipherFile(plainFile, writable, syncPolicy);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Returns the plaintext size of a file.
     *
     * @param plainFile the plaintext file path
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    public long size(String plainFile) throws IOException {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            return fileManager.size(plainFile);
        } finally {
            readLock.unlock();
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
    public byte[] readAll(String plainFile) throws IOException {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            return fileManager.readAll(plainFile);
        } finally {
            readLock.unlock();
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
    public InputStream openRead(String plainFile) throws IOException {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            return fileManager.openRead(plainFile);
        } finally {
            readLock.unlock();
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
    public OutputStream openWrite(String plainFile) throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            return fileManager.openWrite(plainFile);
        } finally {
            writeLock.unlock();
        }
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
    public OutputStream openWrite(String plainFile, SyncPolicy syncPolicy) throws IOException {
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            return fileManager.openWrite(plainFile, syncPolicy);
        } finally {
            writeLock.unlock();
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
    public void write(String plainFile, long offset, byte[] data) throws IOException {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.write(plainFile, offset, data);
        } finally {
            readLock.unlock();
        }
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
    public void write(String plainFile, long offset, byte[] data, SyncPolicy syncPolicy)
            throws IOException {
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.write(plainFile, offset, data, syncPolicy);
        } finally {
            readLock.unlock();
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
    public void truncate(String plainFile, long newSize) throws IOException {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.truncate(plainFile, newSize);
        } finally {
            readLock.unlock();
        }
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
    public void truncate(String plainFile, long newSize, SyncPolicy syncPolicy)
            throws IOException {
        Objects.requireNonNull(syncPolicy, "syncPolicy");
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.truncate(plainFile, newSize, syncPolicy);
        } finally {
            readLock.unlock();
        }
    }

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
    public void setTimes(String plainPath, @Nullable FileTime lastModifiedTime,
                         @Nullable FileTime lastAccessTime, @Nullable FileTime createTime)
            throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.setTimes(plainPath, lastModifiedTime, lastAccessTime, createTime);
        } finally {
            writeLock.unlock();
        }
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
    public void checkAccess(String plainPath, AccessMode... modes) throws IOException {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            if (readOnly) {
                for (AccessMode mode : modes) {
                    if (mode == AccessMode.WRITE) {
                        throw new AccessDeniedException(plainPath, null,
                                "filesystem is read-only");
                    }
                }
            }
            fileManager.checkAccess(plainPath, modes);
        } finally {
            readLock.unlock();
        }
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
    public @Nullable PosixFileAttributes posixAttributes(String plainPath) throws IOException {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            return fileManager.posixAttributes(plainPath);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Sets the POSIX permissions of a plaintext path's backing cipher file.
     *
     * @param plainPath   the plaintext path
     * @param permissions the new permissions
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} or {@code permissions} is {@code null}
     */
    public void setPosixPermissions(String plainPath, Set<PosixFilePermission> permissions)
            throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.setPosixPermissions(plainPath, permissions);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Sets the POSIX owner of a plaintext path's backing cipher file.
     *
     * @param plainPath the plaintext path
     * @param owner     the new owner
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} or {@code owner} is {@code null}
     */
    public void setPosixOwner(String plainPath, UserPrincipal owner) throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.setPosixOwner(plainPath, owner);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Sets the POSIX group of a plaintext path's backing cipher file.
     *
     * @param plainPath the plaintext path
     * @param group     the new group
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} or {@code group} is {@code null}
     */
    public void setPosixGroup(String plainPath, GroupPrincipal group) throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.setPosixGroup(plainPath, group);
        } finally {
            writeLock.unlock();
        }
    }

    // ------------------------------------------------------------------
    // Create / delete / rename (delegated)
    // ------------------------------------------------------------------

    /**
     * Creates an empty file (fails if it already exists).
     *
     * @param plainFile the plaintext file path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    public void createFile(String plainFile) throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.createFile(plainFile);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Creates a directory (including its diriv).
     *
     * @param plainDir the plaintext directory path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    public void mkdir(String plainDir) throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.mkdir(plainDir);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Deletes a file, symlink or empty directory.
     *
     * @param plainPath the plaintext path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    public void delete(String plainPath) throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.delete(plainPath);
        } finally {
            writeLock.unlock();
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
     * subtree. An existing file or symlink target is replaced atomically;
     * only a directory target is removed first, after verifying it is empty
     * apart from its {@code gocryptfs.diriv}.</p>
     *
     * @param plainFrom       the plaintext source path
     * @param plainTo         the plaintext target path
     * @param replaceExisting whether an existing target (a file, symlink or
     *                        empty directory) may be replaced
     * @throws java.nio.file.NoSuchFileException if the source or the target's parent does not exist
     * @throws java.nio.file.FileAlreadyExistsException if the target exists and {@code replaceExisting} is {@code false}
     * @throws java.nio.file.DirectoryNotEmptyException if the target is a non-empty directory
     * @throws IOException if the target lies inside the source or on filesystem errors
     * @throws NullPointerException if an argument is {@code null}
     */
    public void rename(String plainFrom, String plainTo, boolean replaceExisting)
            throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.rename(plainFrom, plainTo, replaceExisting);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Creates a symlink pointing to {@code target}.
     *
     * @param plainPath the plaintext symlink path
     * @param target    the plaintext target
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plainPath} or {@code target} is {@code null}
     */
    public void createSymlink(String plainPath, String target) throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ensureOpen();
            ensureWritable();
            fileManager.createSymlink(plainPath, target);
        } finally {
            writeLock.unlock();
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
    public String readSymlinkTarget(String plainPath) throws IOException {
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            ensureOpen();
            return fileManager.readSymlinkTarget(plainPath);
        } finally {
            readLock.unlock();
        }
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /**
     * Derives a fresh content-encryption helper from the master key. Each
     * returned instance owns its own key material and must be wiped by its
     * consumer (a file/stream/handle on close, or a transient use immediately
     * afterwards). The master key itself is owned by this filesystem and is
     * wiped only on {@link #close()}.
     *
     * @return a new content-encryption helper
     */
    private ContentEnc deriveContentEnc() {
        return config.contentEnc(masterKey);
    }

    /**
     * Wipes the master key and the EME name-encryption key, and clears the
     * directory-IV cache. This is the secret-destruction part of
     * {@link #close()}; it deliberately does not touch the store. Content keys
     * are owned per resource and are wiped by those resources on their own
     * close.
     */
    private void wipeSecrets() {
        directoryManager.clearDirIvCache();
        eme.wipe();
        Keys.wipe(masterKey);
    }

    /**
     * Closes this filesystem, flushing any pending cipher file writes, wiping
     * the master key and every key derived from it and, when this instance
     * created the store itself (via the URI-based factories), closing the store.
     *
     * <p>Closing takes the write lock and excludes every open channel
     * operation, so it waits for every operation that already holds the read
     * or write lock (including buffered channel I/O) before flushing and
     * wiping; operations started after the close has begun fail. Closing is
     * idempotent. A store supplied directly to {@code open}/{@code create} is
     * owned by the caller and is left open.</p>
     *
     * @throws IOException if a pending write cannot be flushed or the store cannot be closed
     */
    @Override
    public void close() throws IOException {
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            IOException failure = null;
            // Exclude every open channel operation, reject new ones, and keep
            // that exclusion across both the flush and the key wipe. Otherwise
            // a channel write could land after flushSharedFiles() but before
            // wipeSecrets() and be lost or fail against wiped keys.
            Lock channelLock = fileManager.lockChannelsForClose();
            try {
                try {
                    // Flush before the keys are wiped so buffered plaintext
                    // can still be encrypted; every entry is flushed, with
                    // failures collected.
                    fileManager.flushSharedFiles();
                } catch (IOException e) {
                    failure = e;
                }
                try {
                    wipeSecrets();
                } finally {
                    if (rootLock != null) {
                        try {
                            rootLock.close();
                        } catch (IOException e) {
                            if (failure == null) {
                                failure = e;
                            } else {
                                failure.addSuppressed(e);
                            }
                        }
                    }
                    if (ownsStore) {
                        try {
                            store.close();
                        } catch (IOException e) {
                            if (failure == null) {
                                failure = e;
                            } else {
                                failure.addSuppressed(e);
                            }
                        }
                    }
                }
            } finally {
                channelLock.unlock();
            }
            if (failure != null) {
                throw failure;
            }
        } finally {
            writeLock.unlock();
        }
    }
}
