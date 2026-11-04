package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.config.ConfigFile;
import de.sfuhrm.gocryptfs4j.config.Fido2Params;
import de.sfuhrm.gocryptfs4j.crypto.AesBlockCipher;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Eme;
import de.sfuhrm.gocryptfs4j.crypto.Hkdf;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.CipherStores;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.AccessMode;
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
 * <p>Sensitive input buffers supplied by the caller &mdash; the password
 * {@code char[]} and the raw master-key {@code byte[]} &mdash; are read but
 * neither retained nor wiped by this class: the caller keeps ownership of them
 * and should clear them once they are no longer needed. A password is encoded
 * as UTF-8 before it is passed to scrypt, matching the raw bytes gocryptfs
 * reads from a UTF-8 terminal, passfile or extpass program. The master key that
 * the returned instance derives, and every sub-key derived from it, are owned
 * by that instance and wiped on {@link #close()}. A raw master-key array is
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

    /** The parsed configuration file. */
    private ConfigFile config;

    /** The 32-byte master key. */
    private final byte[] masterKey;

    /** The EME name-encryption helper. */
    private final Eme eme;

    /** The content-encryption helper. */
    private final ContentEnc contentEnc;

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
     * Creates an instance, called after the master key has been unlocked.
     *
     * @param store     the ciphertext-side store
     * @param config    the parsed configuration
     * @param masterKey the 32-byte master key
     */
    private GocryptFs(CipherStore store, ConfigFile config, byte[] masterKey) {
        this(store, config, masterKey, false);
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
        String root = store.root();
        boolean plainNames = config.plaintextNames();
        boolean dirIv = config.dirIv();
        boolean deterministic = !plainNames && !dirIv;

        Eme emeHelper = null;
        ContentEnc contentEncHelper = null;
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
            contentEncHelper = config.contentEnc(masterKey);
            NameTransform nameTransformHelper = new NameTransform(emeHelper, config.longNames(),
                    config.longNameMax(), config.raw64(), deterministic);

            this.store = store;
            this.rootName = root;
            this.config = config;
            this.masterKey = masterKey;
            this.ownsStore = ownsStore;
            this.plaintextNames = plainNames;
            this.eme = emeHelper;
            this.contentEnc = contentEncHelper;
            this.nameManager = new NameManager(nameTransformHelper, plainNames, store);
            this.directoryManager = new DirectoryManager(store, root, plainNames, deterministic,
                    nameTransformHelper, contentEncHelper, this.nameManager);
            this.pathResolver = new PathResolver(store, root, plainNames,
                    this.nameManager, this.directoryManager);
            this.fileManager = new FileManager(store, contentEncHelper, nameTransformHelper,
                    plainNames, this.nameManager, this.directoryManager, this.pathResolver);
            this.directoryManager.setFileManager(this.fileManager);
            constructed = true;
        } finally {
            if (!constructed) {
                // The constructor is aborting before ownership of the key
                // material transfers to the instance: wipe everything derived
                // here, including the master key.
                if (contentEncHelper != null) {
                    contentEncHelper.wipe();
                }
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
        return open(store, password, false);
    }

    /**
     * Opens an existing cipher store, unlocking the master key from
     * {@code password}, recording whether the returned instance owns
     * {@code store}.
     */
    private static GocryptFs open(CipherStore store, char[] password, boolean ownsStore)
            throws IOException {
        ConfigFile config = ConfigFile.load(store);
        byte[] masterKey = config.decryptMasterKey(password);
        return new GocryptFs(store, config, masterKey, ownsStore);
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
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(masterKey, "masterKey");
        if (masterKey.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("master key must be "
                    + Constants.KEY_LEN + " bytes");
        }
        ConfigFile config = ConfigFile.load(store);
        return new GocryptFs(store, config, masterKey.clone());
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
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(token, "token");
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
            return new GocryptFs(store, config, masterKey);
        } catch (IOException e) {
            if (e.getCause() instanceof GeneralSecurityException) {
                throw new IOException("FIDO2 HMAC secret did not unlock the master key "
                        + "(wrong security key or credential?)", e);
            }
            throw e;
        } finally {
            Keys.wipe(secret);
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
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(password, "password");
        CipherStore store = CipherStores.newStore(uri, env);
        boolean ok = false;
        try {
            GocryptFs fs = open(store, password, true);
            ok = true;
            return fs;
        } finally {
            if (!ok) {
                store.close();
            }
        }
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
     * Creates a new filesystem, recording whether the returned instance owns
     * {@code store} and must close it on {@link #close()}.
     */
    private static GocryptFs create(CipherStore store, char[] password, boolean plaintextNames,
                                    ContentCipherType cipherType, boolean ownsStore)
            throws IOException {
        if (!store.list(store.root()).isEmpty()) {
            throw new IOException("cipher dir is not empty: " + store.root());
        }
        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
        boolean ok = false;
        try {
            ConfigFile config = ConfigFile.create(masterKey, password, plaintextNames, cipherType);
            store.writeConfig(PathResolver.join(store.root(), Constants.CONF_DEFAULT_NAME),
                    config.toBytes(), false);
            GocryptFs fs = new GocryptFs(store, config, masterKey, ownsStore);
            try {
                if (!plaintextNames) {
                    fs.directoryManager.writeDirIV(store.root());
                }
                ok = true;
                return fs;
            } catch (IOException e) {
                fs.wipeSecrets();
                FileManager.deleteIfExists(store,
                        PathResolver.join(store.root(), Constants.CONF_DEFAULT_NAME));
                throw e;
            }
        } finally {
            if (!ok) {
                Keys.wipe(masterKey);
            }
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
        if (!store.list(store.root()).isEmpty()) {
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
            boolean ok = false;
            try {
                ConfigFile config = ConfigFile.create(masterKey, secret, plaintextNames, cipherType,
                        new Fido2Params(credentialId, hmacSalt, options));
                store.writeConfig(PathResolver.join(store.root(), Constants.CONF_DEFAULT_NAME),
                        config.toBytes(), false);
                GocryptFs fs = new GocryptFs(store, config, masterKey);
                try {
                    if (!plaintextNames) {
                        fs.directoryManager.writeDirIV(store.root());
                    }
                    ok = true;
                    return fs;
                } catch (IOException e) {
                    fs.wipeSecrets();
                    FileManager.deleteIfExists(store,
                            PathResolver.join(store.root(), Constants.CONF_DEFAULT_NAME));
                    throw e;
                }
            } finally {
                if (!ok) {
                    Keys.wipe(masterKey);
                }
            }
        } finally {
            Keys.wipe(secret);
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
        return plaintextNames;
    }

    /**
     * Returns the read lock guarding read operations (listing, stat, reads and
     * content writes to existing files).
     *
     * @return the read lock
     */
    public Lock readLock() {
        return lock.readLock();
    }

    /**
     * Returns the write lock guarding namespace-mutating operations (create,
     * delete, rename, mkdir and open).
     *
     * @return the write lock
     */
    public Lock writeLock() {
        return lock.writeLock();
    }

    /**
     * Changes the password protecting this filesystem's master key and writes
     * the updated {@code gocryptfs.conf} atomically.
     *
     * <p>This is the equivalent of gocryptfs's {@code -passwd}. The master key
     * itself is unchanged, so the ciphertext of every existing file remains
     * valid; only the scrypt salt and the encrypted master-key blob are
     * rewritten. The supplied password is read but neither retained nor wiped
     * by this class, so the caller should clear it when it is no longer
     * needed.</p>
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
        Objects.requireNonNull(password, "password");
        Lock writeLock = lock.writeLock();
        writeLock.lock();
        try {
            ConfigFile updated = config.reencryptMasterKeyCopy(masterKey, password);
            store.writeConfig(PathResolver.join(rootName, Constants.CONF_DEFAULT_NAME),
                    updated.toBytes(), true);
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
        return pathResolver.resolve(plainPath);
    }

    // ------------------------------------------------------------------
    // Listing
    // ------------------------------------------------------------------

    /**
     * Lists a plaintext directory path, returning entries sorted by name.
     *
     * @param plainDir the plaintext directory path
     * @return the directory entries sorted by plaintext name
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    public List<DirEntry> list(String plainDir) throws IOException {
        Objects.requireNonNull(plainDir, "plainDir");
        Lock readLock = lock.readLock();
        readLock.lock();
        try {
            PathResolver.Resolved r = pathResolver.resolve(plainDir);
            byte[] iv = directoryManager.readDirIV(r.cipherPath);
            List<DirEntry> entries = directoryManager.listCipherDir(r.cipherPath, iv);
            entries.sort(Comparator.comparing(DirEntry::plainName));
            return entries;
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
            return fileManager.openCipherFile(plainFile, writable);
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
            return fileManager.openWrite(plainFile);
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
            fileManager.write(plainFile, offset, data);
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
            fileManager.truncate(plainFile, newSize);
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
            return fileManager.readSymlinkTarget(plainPath);
        } finally {
            readLock.unlock();
        }
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /**
     * Wipes the master key and every key derived from it, and clears the
     * directory-IV cache. This is the secret-destruction part of
     * {@link #close()}; it deliberately does not touch the store.
     */
    private void wipeSecrets() {
        directoryManager.clearDirIvCache();
        eme.wipe();
        contentEnc.wipe();
        Keys.wipe(masterKey);
    }

    /**
     * Closes this filesystem, flushing any pending cipher file writes, wiping
     * the master key and every key derived from it and, when this instance
     * created the store itself (via the URI-based factories), closing the store.
     *
     * <p>Closing is idempotent. A store supplied directly to
     * {@code open}/{@code create} is owned by the caller and is left open.</p>
     *
     * @throws IOException if a pending write cannot be flushed or the store cannot be closed
     */
    @Override
    public void close() throws IOException {
        IOException failure = null;
        try {
            // Flush before the keys are wiped so buffered plaintext can still
            // be encrypted; every entry is flushed, with failures collected.
            fileManager.flushSharedFiles();
        } catch (IOException e) {
            failure = e;
        }
        try {
            wipeSecrets();
        } finally {
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
        if (failure != null) {
            throw failure;
        }
    }
}
