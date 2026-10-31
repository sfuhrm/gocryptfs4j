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
    private final ConfigFile config;

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
     * Returns whether file names are stored unencrypted.
     *
     * @return true if file names are stored unencrypted
     */
    public boolean plaintextNames() {
        return plaintextNames;
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
        config.reencryptMasterKey(masterKey, password);
        store.writeConfig(PathResolver.join(rootName, Constants.CONF_DEFAULT_NAME),
                config.toBytes(), true);
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
        PathResolver.Resolved r = pathResolver.resolve(plainDir);
        byte[] iv = directoryManager.readDirIV(r.cipherPath);
        List<DirEntry> entries = directoryManager.listCipherDir(r.cipherPath, iv);
        entries.sort(Comparator.comparing(DirEntry::plainName));
        return entries;
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
        return fileManager.stat(plainPath);
    }

    /**
     * Opens a plaintext file for random access.
     *
     * @param plainFile the plaintext file path
     * @param writable  whether to open for writing
     * @return the opened cipher file
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    public CipherFile openCipherFile(String plainFile, boolean writable) throws IOException {
        return fileManager.openCipherFile(plainFile, writable);
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
        return fileManager.size(plainFile);
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
        return fileManager.readAll(plainFile);
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
        return fileManager.openRead(plainFile);
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
        return fileManager.openWrite(plainFile);
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
        fileManager.write(plainFile, offset, data);
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
        fileManager.truncate(plainFile, newSize);
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
        fileManager.setTimes(plainPath, lastModifiedTime, lastAccessTime, createTime);
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
        fileManager.checkAccess(plainPath, modes);
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
        return fileManager.posixAttributes(plainPath);
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
        fileManager.setPosixPermissions(plainPath, permissions);
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
        fileManager.setPosixOwner(plainPath, owner);
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
        fileManager.setPosixGroup(plainPath, group);
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
        fileManager.createFile(plainFile);
    }

    /**
     * Creates a directory (including its diriv).
     *
     * @param plainDir the plaintext directory path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    public void mkdir(String plainDir) throws IOException {
        fileManager.mkdir(plainDir);
    }

    /**
     * Deletes a file, symlink or empty directory.
     *
     * @param plainPath the plaintext path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    public void delete(String plainPath) throws IOException {
        fileManager.delete(plainPath);
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
        fileManager.rename(plainFrom, plainTo, replaceExisting);
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
        fileManager.createSymlink(plainPath, target);
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
        return fileManager.readSymlinkTarget(plainPath);
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
     * Closes this filesystem, wiping the master key and every key derived from
     * it and, when this instance created the store itself (via the URI-based
     * factories), closing the store.
     *
     * <p>Closing is idempotent. A store supplied directly to
     * {@code open}/{@code create} is owned by the caller and is left open.</p>
     *
     * @throws IOException if the store cannot be closed
     */
    @Override
    public void close() throws IOException {
        wipeSecrets();
        if (ownsStore) {
            store.close();
        }
    }
}
