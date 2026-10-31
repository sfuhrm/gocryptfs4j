package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.config.ConfigFile;
import de.sfuhrm.gocryptfs4j.config.ContentCipherType;
import de.sfuhrm.gocryptfs4j.config.Fido2Params;
import de.sfuhrm.gocryptfs4j.crypto.AesBlockCipher;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Eme;
import de.sfuhrm.gocryptfs4j.crypto.Hkdf;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.CipherStores;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
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
import java.util.concurrent.ConcurrentHashMap;

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

    /** The name-transform helper. */
    private final NameTransform nameTransform;

    /** Whether file names are stored unencrypted. */
    private final boolean plaintextNames;

    /** Whether deterministic (no per-directory IV) name encryption is used. */
    private final boolean deterministicNames;

    /** Cache of per-directory IVs, keyed by cipher directory name. */
    private final Map<String, byte[]> dirIvCache = new ConcurrentHashMap<>();

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
            this.deterministicNames = deterministic;
            this.eme = emeHelper;
            this.contentEnc = contentEncHelper;
            this.nameTransform = nameTransformHelper;
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
            store.writeConfig(join(store.root(), Constants.CONF_DEFAULT_NAME), config.toBytes(), false);
            GocryptFs fs = new GocryptFs(store, config, masterKey, ownsStore);
            try {
                if (!plaintextNames) {
                    fs.writeDirIV(store.root());
                }
                ok = true;
                return fs;
            } catch (IOException e) {
                fs.wipeSecrets();
                deleteIfExists(store, join(store.root(), Constants.CONF_DEFAULT_NAME));
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
        String name = userName != null ? userName : baseName(store.root());

        byte[] credentialId = token.registerCredential(name);
        byte[] hmacSalt = Keys.randomBytes(Fido2Params.HMAC_SALT_LEN);
        byte[] secret = token.hmacSecret(credentialId, hmacSalt, options);
        try {
            byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
            boolean ok = false;
            try {
                ConfigFile config = ConfigFile.create(masterKey, secret, plaintextNames, cipherType,
                        new Fido2Params(credentialId, hmacSalt, options));
                store.writeConfig(join(store.root(), Constants.CONF_DEFAULT_NAME), config.toBytes(), false);
                GocryptFs fs = new GocryptFs(store, config, masterKey);
                try {
                    if (!plaintextNames) {
                        fs.writeDirIV(store.root());
                    }
                    ok = true;
                    return fs;
                } catch (IOException e) {
                    fs.wipeSecrets();
                    deleteIfExists(store, join(store.root(), Constants.CONF_DEFAULT_NAME));
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
     * Returns the configuration file.
     *
     * @return the configuration file
     */
    ConfigFile config() {
        return config;
    }

    /**
     * Returns the content-encryption helper.
     *
     * @return the content-encryption helper
     */
    ContentEnc contentEnc() {
        return contentEnc;
    }

    /**
     * Returns the name-transform helper.
     *
     * @return the name-transform helper
     */
    NameTransform nameTransform() {
        return nameTransform;
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
        store.writeConfig(join(rootName, Constants.CONF_DEFAULT_NAME), config.toBytes(), true);
    }

    // ------------------------------------------------------------------
    // Directory IV management
    // ------------------------------------------------------------------

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
        byte[] data = store.readSmall(join(cipherDir, Constants.DIR_IV_FILENAME), Constants.DIR_IV_LEN);
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
     * Creates a {@code gocryptfs.diriv} in {@code cipherDir}.
     *
     * @param cipherDir the ciphertext directory name
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} is {@code null}
     */
    void writeDirIV(String cipherDir) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        if (plaintextNames || deterministicNames) {
            return;
        }
        store.writeSmall(join(cipherDir, Constants.DIR_IV_FILENAME), Keys.randomBytes(Constants.DIR_IV_LEN),
                false);
        dirIvCache.remove(cipherDir);
    }

    /**
     * Removes any cached directory IVs at or below {@code dir}.
     *
     * @param dir the cipher directory whose subtree is no longer valid
     */
    private void invalidateDirIvCache(String dir) {
        if (dirIvCache.isEmpty()) {
            return;
        }
        dirIvCache.keySet().removeIf(k -> k.equals(dir) || k.startsWith(dir + "/"));
    }

    // ------------------------------------------------------------------
    // Name mapping
    // ------------------------------------------------------------------

    /**
     * Encrypts (and possibly hashes) a plaintext name using {@code dirIV}.
     *
     * @param plainName the plaintext name
     * @param dirIV     the 16-byte directory IV
     * @return the ciphertext name
     * @throws NullPointerException if {@code plainName} or {@code dirIV} is {@code null}
     * @throws FileSystemException if {@code plainName} is longer than the 255-byte
     *                             name limit
     */
    String cipherNameFor(String plainName, byte[] dirIV) throws IOException {
        Objects.requireNonNull(plainName, "plainName");
        Objects.requireNonNull(dirIV, "dirIV");
        if (plainName.getBytes(StandardCharsets.UTF_8).length > Constants.NAME_MAX) {
            throw new FileSystemException(plainName, null, "File name too long");
        }
        if (plaintextNames) {
            return plainName;
        }
        return nameTransform.encryptAndHashName(plainName, dirIV);
    }

    /**
     * Decrypts a cipher name using {@code dirIV}.
     *
     * @param cipherName the ciphertext name
     * @param dirIV      the 16-byte directory IV
     * @return the plaintext name
     * @throws NullPointerException if {@code cipherName} or {@code dirIV} is {@code null}
     */
    String plainNameFor(String cipherName, byte[] dirIV) {
        Objects.requireNonNull(cipherName, "cipherName");
        Objects.requireNonNull(dirIV, "dirIV");
        if (plaintextNames) {
            return cipherName;
        }
        return nameTransform.decryptName(cipherName, dirIV);
    }

    // ------------------------------------------------------------------
    // Path resolution
    // ------------------------------------------------------------------

    /** Result of resolving a plaintext path to a cipher-side path. */
    static final class Resolved {
        /** The ciphertext-side name. */
        public final String cipherPath;
        /** The ciphertext-side parent name, or {@code null} for the root. */
        public final @Nullable String cipherParent;
        /** The 16-byte IV of the parent directory. */
        public final byte[] parentDirIV;
        /** The ciphertext (encrypted) name, or {@code null} for the root. */
        public final @Nullable String cipherName;
        /** The plaintext (decrypted) name. */
        public final String plainName;

        /**
         * Creates a resolution result.
         *
         * @param cipherPath   the ciphertext-side name
         * @param cipherParent the ciphertext-side parent name, or {@code null} for the root
         * @param parentDirIV  the 16-byte IV of the parent directory
         * @param cipherName   the ciphertext (encrypted) name, or {@code null} for the root
         * @param plainName    the plaintext (decrypted) name
         */
        Resolved(String cipherPath, @Nullable String cipherParent, byte[] parentDirIV,
                 @Nullable String cipherName, String plainName) {
            this.cipherPath = cipherPath;
            this.cipherParent = cipherParent;
            this.parentDirIV = parentDirIV;
            this.cipherName = cipherName;
            this.plainName = plainName;
        }
    }

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
    Resolved resolve(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        List<String> comps = normalize(plainPath);
        checkNotControlFile(comps);
        String cur = rootName;
        byte[] curIV = readDirIV(cur);
        for (int i = 0; i < comps.size() - 1; i++) {
            String cName = cipherNameFor(comps.get(i), curIV);
            cur = join(cur, cName);
            checkIntermediateDirectory(cur);
            curIV = readDirIV(cur);
        }
        if (comps.isEmpty()) {
            return new Resolved(rootName, null, curIV, null, "");
        }
        String plainName = comps.get(comps.size() - 1);
        String cName = cipherNameFor(plainName, curIV);
        return new Resolved(join(cur, cName), cur, curIV, cName, plainName);
    }

    /**
     * Resolves the parent directory and basename of a plaintext path.
     *
     * @param plainPath the plaintext path
     * @return the resolution result for the path's final component
     * @throws IOException if the path is empty or the parent cannot be resolved
     */
    private Resolved resolveParent(String plainPath) throws IOException {
        List<String> comps = normalize(plainPath);
        checkNotControlFile(comps);
        if (comps.isEmpty()) {
            throw new IOException("invalid path: " + plainPath);
        }
        String plainName = comps.remove(comps.size() - 1);
        String cur = rootName;
        byte[] curIV = readDirIV(cur);
        for (String c : comps) {
            String cName = cipherNameFor(c, curIV);
            cur = join(cur, cName);
            checkIntermediateDirectory(cur);
            curIV = readDirIV(cur);
        }
        String cName = cipherNameFor(plainName, curIV);
        return new Resolved(join(cur, cName), cur, curIV, cName, plainName);
    }

    /**
     * Verifies that an intermediate path component is a real directory, not a
     * symbolic link. Following a symlink here would allow escaping the cipher
     * root (for example in plaintext-names mode, where a symlink such as
     * {@code /l -> /etc} could redirect writes outside the root).
     *
     * @param dir the resolved intermediate component
     * @throws NotDirectoryException if {@code dir} is not a directory or is a
     *                               symbolic link
     */
    private void checkIntermediateDirectory(String dir) throws IOException {
        if (!store.stat(dir).isDirectory()) {
            throw new NotDirectoryException(dir);
        }
    }

    /**
     * Rejects a plaintext path that would map to a reserved control file.
     *
     * <p>Encrypted file names are base64url and can never equal a control-file
     * name (which contains a dot), so the collision only exists in
     * plaintext-names mode, where the cipher name equals the plaintext name.
     * Only the top-level {@code /gocryptfs.conf} is reserved; a same-named
     * entry in a subdirectory is an ordinary file.</p>
     *
     * @param comps the normalized plaintext path components
     * @throws IllegalArgumentException if the path targets the config file
     */
    private void checkNotControlFile(List<String> comps) {
        if (plaintextNames && !comps.isEmpty()
                && comps.get(0).equals(Constants.CONF_DEFAULT_NAME)) {
            throw new IllegalArgumentException("reserved control file: " + Constants.CONF_DEFAULT_NAME);
        }
    }

    /**
     * Splits and normalizes a plaintext path into its components.
     *
     * @param path the plaintext path
     * @return the path components, without empty, {@code "."} or {@code ".."} parts
     * @throws IllegalArgumentException if the path contains a {@code ".."} component
     */
    private static List<String> normalize(String path) {
        List<String> out = new ArrayList<>();
        if (path == null || path.isEmpty() || path.equals("/")) {
            return out;
        }
        for (String seg : path.split("/", -1)) {
            if (seg.isEmpty() || seg.equals(".")) {
                continue;
            }
            if (seg.equals("..")) {
                throw new IllegalArgumentException("'..' is not supported: " + path);
            }
            out.add(seg);
        }
        return out;
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
        Resolved r = resolve(plainDir);
        byte[] iv = readDirIV(r.cipherPath);
        List<DirEntry> entries = listCipherDir(r.cipherPath, iv);
        entries.sort(Comparator.comparing(DirEntry::plainName));
        return entries;
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
                int t = nameTransform.nameType(cName);
                if (t == NameTransform.LONG_NAME_FILENAME) {
                    continue;
                }
                if (t == NameTransform.LONG_NAME_CONTENT) {
                    String nameFile = join(cipherDir, cName + Constants.LONG_NAME_SUFFIX);
                    byte[] nameBytes;
                    try {
                        nameBytes = store.readSmall(nameFile, Constants.LONG_NAME_CONTENT_MAX_SIZE);
                    } catch (IOException e) {
                        // A missing, oversized or otherwise unreadable .name
                        // file is treated like a corrupt name: skip it.
                        continue;
                    }
                    cipherName = new String(nameBytes, StandardCharsets.UTF_8);
                }
            }

            String plainName;
            try {
                plainName = plainNameFor(cipherName, iv);
            } catch (IllegalArgumentException e) {
                // Skip undecryptable (corrupt) entries.
                continue;
            }
            if (!isValidPlainName(plainName)) {
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
                    target = readSymlink(join(cipherDir, cName));
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

    /**
     * Returns whether a decrypted name is safe to use as a single path
     * component.
     *
     * @param name the decrypted name
     * @return {@code false} if {@code name} is empty, {@code "."}, {@code ".."},
     *         or contains a path separator or NUL byte
     */
    private static boolean isValidPlainName(String name) {
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '/' || c == '\\' || c == '\0') {
                return false;
            }
        }
        return true;
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
        String target = store.readSymlink(cipherSymlink);
        if (plaintextNames) {
            return target;
        }
        if (target.isEmpty()) {
            return "";
        }
        byte[] cData = nameTransform.b64Decode(target);
        try {
            byte[] data = contentEnc.decryptBlock(cData, 0, null);
            return new String(data, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException("corrupt symlink target", e);
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
        Objects.requireNonNull(plainPath, "plainPath");
        Resolved r = resolve(plainPath);
        return readSymlink(r.cipherPath);
    }

    // ------------------------------------------------------------------
    // Content access
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
        Objects.requireNonNull(plainPath, "plainPath");
        Resolved r = resolve(plainPath);
        return statResolved(r);
    }

    /**
     * Reads the attributes of an already-resolved path.
     *
     * @param r the resolved path
     * @return the directory entry
     * @throws IOException on filesystem errors
     */
    private DirEntry statResolved(Resolved r) throws IOException {
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
            size = contentEnc.cipherSizeToPlainSize(node.size());
        } else {
            kind = DirEntry.Kind.OTHER;
            size = node.size();
        }
        String plainName = r.plainName.isEmpty() ? "/" : r.plainName;
        return new DirEntry(plainName, r.cipherName, store.posixAttributes(r.cipherPath), kind, size,
                node.lastModifiedTime(), node.lastAccessTime(), node.creationTime(),
                node.fileKey());
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
        Objects.requireNonNull(plainFile, "plainFile");
        Resolved r = resolve(plainFile);
        return openCipherFileByName(r.cipherPath, writable);
    }

    /**
     * Opens a cipher-side file for random access.
     *
     * @param cipherFile the ciphertext file name
     * @param writable   whether to open for writing
     * @return the opened cipher file
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherFile} is {@code null}
     */
    CipherFile openCipherFileByName(String cipherFile, boolean writable) throws IOException {
        Objects.requireNonNull(cipherFile, "cipherFile");
        CipherChannel channel = store.open(cipherFile, writable);
        return CipherFile.open(channel, contentEnc, writable);
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
        Objects.requireNonNull(plainFile, "plainFile");
        Resolved r = resolve(plainFile);
        try (CipherFile cf = openCipherFileByName(r.cipherPath, false)) {
            return cf.plainSize();
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
        Objects.requireNonNull(plainFile, "plainFile");
        Resolved r = resolve(plainFile);
        try (CipherFile cf = openCipherFileByName(r.cipherPath, false)) {
            long size = cf.plainSize();
            if (size > Integer.MAX_VALUE) {
                throw new IOException("file too large to read into memory: " + size);
            }
            byte[] out = new byte[(int) size];
            int pos = 0;
            while (pos < size) {
                int n = cf.read(ByteBuffer.wrap(out, pos, (int) (size - pos)), pos);
                if (n < 0) {
                    break;
                }
                pos += n;
            }
            return Arrays.copyOf(out, pos);
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
        Objects.requireNonNull(plainFile, "plainFile");
        Resolved r = resolve(plainFile);
        CipherFile cf = openCipherFileByName(r.cipherPath, false);
        try {
            return new CipherInputStream(cf);
        } catch (RuntimeException e) {
            cf.close();
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
    public OutputStream openWrite(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        Resolved r = resolve(plainFile);
        CipherFile cf = openCipherFileByName(r.cipherPath, true);
        try {
            cf.truncate(0);
            return Channels.newOutputStream(cf.writeChannel(0));
        } catch (IOException | RuntimeException e) {
            cf.close();
            throw e;
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
        Objects.requireNonNull(plainFile, "plainFile");
        Objects.requireNonNull(data, "data");
        if (offset < 0) {
            throw new IllegalArgumentException("negative offset: " + offset);
        }
        Resolved r = resolve(plainFile);
        try (CipherFile cf = openCipherFileByName(r.cipherPath, true)) {
            ByteBuffer buf = ByteBuffer.wrap(data);
            long pos = offset;
            while (buf.hasRemaining()) {
                int n = cf.write(buf, pos);
                if (n <= 0) {
                    throw new IOException("no progress writing to " + plainFile);
                }
                pos += n;
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
    public void truncate(String plainFile, long newSize) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        if (newSize < 0) {
            throw new IllegalArgumentException("negative size: " + newSize);
        }
        Resolved r = resolve(plainFile);
        try (CipherFile cf = openCipherFileByName(r.cipherPath, true)) {
            cf.truncate(newSize);
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
        Objects.requireNonNull(plainPath, "plainPath");
        Resolved r = resolve(plainPath);
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
    public void checkAccess(String plainPath, AccessMode... modes) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Resolved r = resolve(plainPath);
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
    public @Nullable PosixFileAttributes posixAttributes(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Resolved r = resolve(plainPath);
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
    public void setPosixPermissions(String plainPath, Set<PosixFilePermission> permissions)
            throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(permissions, "permissions");
        Resolved r = resolve(plainPath);
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
    public void setPosixOwner(String plainPath, UserPrincipal owner) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(owner, "owner");
        Resolved r = resolve(plainPath);
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
    public void setPosixGroup(String plainPath, GroupPrincipal group) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(group, "group");
        Resolved r = resolve(plainPath);
        store.setPosixGroup(r.cipherPath, group);
    }

    /**
     * A streaming, decrypting {@link InputStream} over a {@link CipherFile}.
     *
     * <p>Buffers decrypted data so that {@link java.io.InputStream#read()}
     * works efficiently. Closing the stream closes the underlying cipher file.</p>
     */
    private static final class CipherInputStream extends InputStream {

        /** The size of the decrypted read-ahead buffer. */
        private static final int BUFFER_SIZE = 8192;

        /** The cipher file being read. */
        private final CipherFile cf;

        /** The current plaintext position. */
        private long pos;

        /** The read-ahead buffer. */
        private final byte[] buf = new byte[BUFFER_SIZE];

        /** The current position within the read-ahead buffer. */
        private int bufPos;

        /** The number of valid bytes in the read-ahead buffer. */
        private int bufLen;

        /**
         * Creates a stream over the given cipher file.
         *
         * @param cf the cipher file to read from
         */
        CipherInputStream(CipherFile cf) {
            this.cf = cf;
        }

        /**
         * Reads a single plaintext byte.
         *
         * @return the byte, or {@code -1} at the end of the stream
         * @throws IOException on filesystem errors
         */
        @Override
        public int read() throws IOException {
            if (bufPos >= bufLen && !fill()) {
                return -1;
            }
            pos++;
            return buf[bufPos++] & 0xFF;
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
            int copied = 0;
            if (bufPos < bufLen) {
                int n = Math.min(len, bufLen - bufPos);
                System.arraycopy(buf, bufPos, b, off, n);
                bufPos += n;
                pos += n;
                copied = n;
                if (copied == len) {
                    return copied;
                }
            }
            int n = cf.read(ByteBuffer.wrap(b, off + copied, len - copied), pos);
            if (n < 0) {
                return copied == 0 ? -1 : copied;
            }
            pos += n;
            return copied + n;
        }

        /**
         * Refills the read-ahead buffer.
         *
         * @return {@code true} if more data was read
         * @throws IOException on filesystem errors
         */
        private boolean fill() throws IOException {
            int n = cf.read(ByteBuffer.wrap(buf), pos);
            if (n <= 0) {
                bufLen = 0;
                return false;
            }
            bufLen = n;
            bufPos = 0;
            return true;
        }

        /**
         * Closes the underlying cipher file and wipes the read-ahead buffer,
         * which holds up to 8 KiB of decrypted plaintext. Calling this method
         * more than once has no effect.
         *
         * @throws IOException on filesystem errors
         */
        @Override
        public void close() throws IOException {
            try {
                cf.close();
            } finally {
                Arrays.fill(buf, (byte) 0);
                bufPos = 0;
                bufLen = 0;
            }
        }
    }

    // ------------------------------------------------------------------
    // Create / delete
    // ------------------------------------------------------------------

    /**
     * Creates an empty file (fails if it already exists).
     *
     * @param plainFile the plaintext file path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    public void createFile(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        Resolved r = resolveParent(plainFile);
        boolean wroteName = prepareLongName(r);
        try {
            store.createFile(r.cipherPath);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                removeLongName(r);
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
    public void mkdir(String plainDir) throws IOException {
        Objects.requireNonNull(plainDir, "plainDir");
        Resolved r = resolveParent(plainDir);
        boolean wroteName = prepareLongName(r);
        try {
            store.mkdir(r.cipherPath);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                removeLongName(r);
            }
            throw e;
        }
        try {
            writeDirIV(r.cipherPath);
        } catch (IOException | RuntimeException e) {
            try {
                deleteIfExists(store, join(r.cipherPath, Constants.DIR_IV_FILENAME));
                store.delete(r.cipherPath);
                removeLongName(r);
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
    public void delete(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Resolved r = resolve(plainPath);
        if (store.stat(r.cipherPath).isDirectory()) {
            // Verify the directory is empty apart from its gocryptfs.diriv
            // before removing anything, so that rejecting a non-empty delete
            // leaves the directory (and its diriv) intact.
            for (CipherNode entry : store.list(r.cipherPath)) {
                if (!entry.name().equals(Constants.DIR_IV_FILENAME)) {
                    throw new DirectoryNotEmptyException(r.cipherPath);
                }
            }
            deleteIfExists(store, join(r.cipherPath, Constants.DIR_IV_FILENAME));
            store.delete(r.cipherPath);
        } else {
            store.delete(r.cipherPath);
        }
        removeLongName(r);
        invalidateDirIvCache(r.cipherPath);
    }

    /**
     * Removes the long-name support file (if any) for the resolved ciphertext
     * entry. Used for both files and directories.
     *
     * @param r the resolved path whose long-name support file may be removed
     * @throws IOException on filesystem errors
     */
    private void removeLongName(Resolved r) throws IOException {
        String cipherName = r.cipherName;
        String cipherParent = r.cipherParent;
        if (plaintextNames || cipherName == null || cipherParent == null
                || !nameTransform.isLongContent(cipherName)) {
            return;
        }
        deleteIfExists(store, join(cipherParent, cipherName + Constants.LONG_NAME_SUFFIX));
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
     * @throws NoSuchFileException if the source or the target's parent does not exist
     * @throws FileAlreadyExistsException if the target exists and {@code replaceExisting} is {@code false}
     * @throws DirectoryNotEmptyException if the target is a non-empty directory
     * @throws IOException if the target lies inside the source or on filesystem errors
     * @throws NullPointerException if an argument is {@code null}
     */
    public void rename(String plainFrom, String plainTo, boolean replaceExisting)
            throws IOException {
        Objects.requireNonNull(plainFrom, "plainFrom");
        Objects.requireNonNull(plainTo, "plainTo");
        List<String> fromComps = normalize(plainFrom);
        List<String> toComps = normalize(plainTo);
        if (fromComps.isEmpty() || toComps.isEmpty()) {
            throw new IOException("cannot rename the root directory");
        }
        Resolved from = resolveParent(plainFrom);
        if (!exists(from.cipherPath)) {
            throw new NoSuchFileException(plainFrom);
        }
        if (fromComps.equals(toComps)) {
            return;
        }
        if (toComps.size() > fromComps.size()
                && toComps.subList(0, fromComps.size()).equals(fromComps)) {
            throw new IOException("cannot move " + plainFrom + " into its own subtree: " + plainTo);
        }
        Resolved to = resolveParent(plainTo);
        if (exists(to.cipherPath)) {
            if (!replaceExisting) {
                throw new FileAlreadyExistsException(plainTo);
            }
            if (store.stat(to.cipherPath).isDirectory()) {
                // A directory can only be replaced when it is empty apart from
                // its gocryptfs.diriv. Verify that before removing anything so a
                // rejected replace leaves the target intact. The empty directory
                // (and its diriv) is then removed explicitly, because an atomic
                // rename cannot replace a directory that still contains its diriv.
                for (CipherNode entry : store.list(to.cipherPath)) {
                    if (!entry.name().equals(Constants.DIR_IV_FILENAME)) {
                        throw new DirectoryNotEmptyException(to.cipherPath);
                    }
                }
                deleteIfExists(store, join(to.cipherPath, Constants.DIR_IV_FILENAME));
                store.delete(to.cipherPath);
                removeLongName(to);
            }
            // A non-directory target is replaced atomically by the rename below.
        }
        boolean wroteName = prepareLongName(to);
        try {
            store.rename(from.cipherPath, to.cipherPath, replaceExisting);
        } catch (IOException | RuntimeException e) {
            // prepareLongName may have created a long-name support file that no
            // longer has a matching entry; drop it so a failed rename leaves no
            // orphan behind.
            if (wroteName) {
                removeLongName(to);
            }
            throw e;
        }
        removeLongName(from);
        invalidateDirIvCache(from.cipherPath);
        invalidateDirIvCache(to.cipherPath);
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
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(target, "target");
        Resolved r = resolveParent(plainPath);
        boolean wroteName = prepareLongName(r);
        try {
            String cTarget = target;
            if (!plaintextNames && !target.isEmpty()) {
                byte[] enc = contentEnc.encryptBlock(target.getBytes(StandardCharsets.UTF_8), 0, null);
                cTarget = nameTransform.b64Encode(enc);
            }
            store.createSymlink(r.cipherPath, cTarget);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                removeLongName(r);
            }
            throw e;
        }
    }

    /**
     * Writes the long-name support file if the cipher name is a long name.
     *
     * @param r the resolved path whose long-name support file may be needed
     * @return {@code true} if a new long-name support file was created and the
     *         caller must remove it should the operation that follows fail
     * @throws IOException on filesystem errors
     */
    private boolean prepareLongName(Resolved r) throws IOException {
        String cipherName = r.cipherName;
        String cipherParent = r.cipherParent;
        if (plaintextNames || cipherName == null || cipherParent == null
                || !nameTransform.isLongContent(cipherName)) {
            return false;
        }
        String nameFile = join(cipherParent, cipherName + Constants.LONG_NAME_SUFFIX);
        byte[] fullCipher = nameTransform.encryptName(r.plainName, r.parentDirIV)
                .getBytes(StandardCharsets.UTF_8);
        try {
            store.writeSmall(nameFile, fullCipher, false);
            return true;
        } catch (FileAlreadyExistsException ignored) {
            // Allowed on rename/overwrite; the existing file is not ours to remove.
            return false;
        }
    }

    /**
     * Wipes the master key and every key derived from it, and clears the
     * directory-IV cache. This is the secret-destruction part of
     * {@link #close()}; it deliberately does not touch the store.
     */
    private void wipeSecrets() {
        dirIvCache.clear();
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

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Joins a ciphertext parent name and a single child name with a slash.
     *
     * @param parent the parent name
     * @param child  the child name
     * @return the joined name
     */
    private static String join(String parent, String child) {
        return parent.isEmpty() ? child : parent + "/" + child;
    }

    /**
     * Returns the base name of a ciphertext root name (the part after the last
     * {@code '/'} or {@code '\'}), used as the default FIDO2 registration user
     * name.
     *
     * @param root the root name
     * @return the base name
     */
    private static String baseName(String root) {
        int idx = Math.max(root.lastIndexOf('/'), root.lastIndexOf('\\'));
        return idx < 0 ? root : root.substring(idx + 1);
    }

    /**
     * Deletes a ciphertext entry, ignoring an already-absent entry.
     *
     * @param store the store
     * @param name  the ciphertext path to delete
     * @throws IOException on storage errors other than the entry being absent
     */
    private static void deleteIfExists(CipherStore store, String name) throws IOException {
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
}
