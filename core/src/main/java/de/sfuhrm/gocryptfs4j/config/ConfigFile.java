package de.sfuhrm.gocryptfs4j.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import de.sfuhrm.gocryptfs4j.crypto.AesSiv;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentCipher;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Gcm;
import de.sfuhrm.gocryptfs4j.crypto.Hkdf;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.crypto.XChaCha20Poly1305;
import de.sfuhrm.gocryptfs4j.core.ContentCipherType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * Parses {@code gocryptfs.conf} and unlocks the master key from a password.
 */
public final class ConfigFile {

    private static final Gson GSON = new GsonBuilder().create();

    /** The creator string written by gocryptfs. */
    @SerializedName("Creator")
    public String creator;

    /** Base64-encoded encrypted master key. */
    @SerializedName("EncryptedKey")
    public String encryptedKey;

    /** The scrypt key-derivation parameters. */
    @SerializedName("ScryptObject")
    public ScryptKdf scryptObject;

    /** The on-disk format version. */
    @SerializedName("Version")
    public int version;

    /** The feature flags enabled for this filesystem. */
    @SerializedName("FeatureFlags")
    public List<String> featureFlags;

    /** The configured long-name limit, or {@code null} for the default. */
    @SerializedName("LongNameMax")
    public Integer longNameMax;

    /** FIDO2 key-protection data, or {@code null} if unused. */
    @SerializedName("FIDO2")
    public Fido2Params fido2;

    private transient byte[] masterKey;

    /** Creates an empty config file (used by Gson and {@link #create}). */
    public ConfigFile() {
    }

    /**
     * Loads and validates a {@code gocryptfs.conf} file.
     *
     * @param path the path to the config file
     * @return the parsed config file
     * @throws IOException if the file is missing, malformed or unsupported
     * @throws NullPointerException if {@code path} is {@code null}
     */
    public static ConfigFile load(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        String json = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        ConfigFile cf = GSON.fromJson(json, ConfigFile.class);
        if (cf == null) {
            throw new IOException("empty config file");
        }
        cf.validate();
        return cf;
    }

    private void validate() throws IOException {
        if (version != Constants.CURRENT_VERSION) {
            throw new IOException("unsupported on-disk format version " + version
                    + " (want " + Constants.CURRENT_VERSION + ")");
        }
        if (featureFlags != null) {
            for (String flag : featureFlags) {
                if (!isKnownFlag(flag)) {
                    throw new IOException("unknown feature flag: " + flag);
                }
            }
        }
        if (isFeatureFlagSet(Constants.FLAG_FIDO2)) {
            if (fido2 == null) {
                throw new IOException("FIDO2 feature flag is set but the FIDO2 object is missing");
            }
            if (fido2.credentialId == null || fido2.credentialId.length == 0) {
                throw new IOException("FIDO2 credential ID is missing");
            }
            if (fido2.hmacSalt == null || fido2.hmacSalt.length == 0) {
                throw new IOException("FIDO2 HMAC salt is missing");
            }
        }
    }

    private static boolean isKnownFlag(String flag) {
        return flag.equals(Constants.FLAG_PLAINTEXT_NAMES)
                || flag.equals(Constants.FLAG_DIR_IV)
                || flag.equals(Constants.FLAG_EME_NAMES)
                || flag.equals(Constants.FLAG_GCM_IV128)
                || flag.equals(Constants.FLAG_LONG_NAMES)
                || flag.equals(Constants.FLAG_LONG_NAME_MAX)
                || flag.equals(Constants.FLAG_AES_SIV)
                || flag.equals(Constants.FLAG_RAW64)
                || flag.equals(Constants.FLAG_HKDF)
                || flag.equals(Constants.FLAG_FIDO2)
                || flag.equals(Constants.FLAG_XCHACHA);
    }

    /**
     * Returns true if the given feature flag is set.
     *
     * @param flag the feature flag name
     * @return true if the flag is set
     * @throws NullPointerException if {@code flag} is {@code null}
     */
    public boolean isFeatureFlagSet(String flag) {
        Objects.requireNonNull(flag, "flag");
        return featureFlags != null && featureFlags.contains(flag);
    }

    /**
     * Derives the scrypt key from the password and decrypts the master key.
     *
     * @param password the password to unlock the master key with
     * @return the 32-byte master key
     * @throws IOException if the password is wrong or the config is malformed
     * @throws NullPointerException if {@code password} is {@code null}
     */
    public byte[] decryptMasterKey(char[] password) throws IOException {
        Objects.requireNonNull(password, "password");
        byte[] passwordBytes = charsToBytes(password);
        try {
            return decryptMasterKey(passwordBytes);
        } finally {
            Keys.wipe(passwordBytes);
        }
    }

    /**
     * Derives the scrypt key from a raw secret and decrypts the master key.
     *
     * <p>This is the FIDO2 code path: gocryptfs uses the raw bytes returned by
     * the token's {@code hmac-secret} extension as the scrypt password.</p>
     *
     * @param secret the raw secret to unlock the master key with
     * @return the 32-byte master key
     * @throws IOException if the secret is wrong or the config is malformed
     * @throws NullPointerException if {@code secret} is {@code null}
     */
    public byte[] decryptMasterKey(byte[] secret) throws IOException {
        Objects.requireNonNull(secret, "secret");
        if (masterKey != null) {
            return masterKey;
        }
        ScryptKdf s = scryptObject;
        byte[] scryptHash = Keys.scrypt(secret, decode(s.salt), s.n, s.r, s.p, s.keyLen);
        try {
            // gocryptfs always protects the master key with AES-256-GCM, even
            // when the content cipher is XChaCha20-Poly1305.
            boolean useHkdf = isFeatureFlagSet(Constants.FLAG_HKDF);
            int ivLen = useHkdf ? Constants.DEFAULT_IV_BITS / 8 : 96 / 8;
            byte[] contentKey = useHkdf
                    ? Hkdf.derive(scryptHash, Constants.HKDF_INFO_GCM_CONTENT, Constants.KEY_LEN)
                    : scryptHash;

            byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKey);
            byte[] nonce = Arrays.copyOfRange(encryptedKeyBytes, 0, ivLen);
            byte[] ct = Arrays.copyOfRange(encryptedKeyBytes, ivLen, encryptedKeyBytes.length);
            // blockNo = 0, fileID = nil -> AAD is eight zero bytes
            byte[] aad = new byte[8];
            masterKey = new Gcm(contentKey).decrypt(ct, nonce, aad);
            if (masterKey.length != Constants.KEY_LEN) {
                throw new IOException("unexpected master key length " + masterKey.length);
            }
            return masterKey;
        } catch (GeneralSecurityException e) {
            throw new IOException("password incorrect", e);
        } finally {
            Keys.wipe(scryptHash);
        }
    }

    private static byte[] charsToBytes(char[] chars) {
        byte[] out = new byte[chars.length];
        for (int i = 0; i < chars.length; i++) {
            out[i] = (byte) chars[i];
        }
        return out;
    }

    /**
     * Re-encrypts the master key with a new password, updating {@link #encryptedKey}
     * and the scrypt salt in place.
     *
     * <p>This is the equivalent of gocryptfs's {@code -passwd}. Because it takes
     * the master key directly, it also supports changing the password without
     * knowing the previous one (gocryptfs's {@code -passwd -masterkey}). The
     * scrypt cost parameters ({@code N}, {@code R}, {@code P}, {@code KeyLen}) and
     * all feature flags are preserved; only the salt is regenerated. Use
     * {@link #writeTo(Path, boolean)} with {@code overwrite = true} afterwards to
     * persist the change.</p>
     *
     * @param masterKey the 32-byte master key
     * @param password  the new password
     * @throws NullPointerException if {@code masterKey} or {@code password} is {@code null}
     * @throws IllegalArgumentException if {@code masterKey} is not 32 bytes long
     */
    public void reencryptMasterKey(byte[] masterKey, char[] password) {
        Objects.requireNonNull(masterKey, "masterKey");
        Objects.requireNonNull(password, "password");
        if (masterKey.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("master key must be "
                    + Constants.KEY_LEN + " bytes");
        }
        ScryptKdf s = scryptObject;
        if (s == null) {
            throw new IllegalStateException("config has no scrypt object");
        }

        byte[] salt = Keys.randomBytes(Constants.KEY_LEN);
        byte[] scryptHash = Keys.scrypt(
                charsToBytes(password), salt, s.n, s.r, s.p, s.keyLen);
        try {
            // The master key is always protected with AES-256-GCM; the content
            // cipher selection only affects file content.
            boolean useHkdf = isFeatureFlagSet(Constants.FLAG_HKDF);
            int ivLen = useHkdf ? Constants.DEFAULT_IV_BITS / 8 : 96 / 8;
            byte[] contentKey = useHkdf
                    ? Hkdf.derive(scryptHash, Constants.HKDF_INFO_GCM_CONTENT, Constants.KEY_LEN)
                    : scryptHash;

            byte[] nonce = Keys.randomBytes(ivLen);
            byte[] aad = new byte[8];
            byte[] ct = new Gcm(contentKey).encrypt(masterKey, nonce, aad);
            byte[] encrypted = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, encrypted, 0, nonce.length);
            System.arraycopy(ct, 0, encrypted, nonce.length, ct.length);

            encryptedKey = Base64.getEncoder().encodeToString(encrypted);
            s.salt = Base64.getEncoder().encodeToString(salt);
            // Invalidate any cached master key so the new password is verified.
            this.masterKey = null;
        } finally {
            Keys.wipe(scryptHash);
            Keys.wipe(salt);
        }
    }

    private static byte[] decode(String b64) {
        return Base64.getDecoder().decode(b64);
    }

    /**
     * Returns true if file names are stored unencrypted.
     *
     * @return true if names are stored unencrypted
     */
    public boolean plaintextNames() {
        return isFeatureFlagSet(Constants.FLAG_PLAINTEXT_NAMES);
    }

    /**
     * Returns true if per-directory IVs are used for name encryption.
     *
     * @return true if per-directory IVs are used
     */
    public boolean dirIv() {
        return isFeatureFlagSet(Constants.FLAG_DIR_IV);
    }

    /**
     * Returns true if long file names may be hashed to {@code gocryptfs.longname.*}.
     *
     * @return true if long names are supported
     */
    public boolean longNames() {
        return isFeatureFlagSet(Constants.FLAG_LONG_NAMES);
    }

    /**
     * Returns the effective long-name limit (255 unless overridden).
     *
     * @return the effective long-name limit in bytes
     */
    public int longNameMax() {
        if (longNames() && longNameMax != null) {
            return longNameMax;
        }
        return Constants.NAME_MAX;
    }

    /**
     * Returns true if file names use raw (unpadded) base64url.
     *
     * @return true if raw base64url is used
     */
    public boolean raw64() {
        return isFeatureFlagSet(Constants.FLAG_RAW64);
    }

    /**
     * Returns true if sub-keys are derived from the master key via HKDF.
     *
     * @return true if HKDF is used
     */
    public boolean hkdf() {
        return isFeatureFlagSet(Constants.FLAG_HKDF);
    }

    /**
     * Returns true if content is encrypted with XChaCha20-Poly1305.
     *
     * @return true if XChaCha20-Poly1305 is used
     */
    public boolean xchacha() {
        return isFeatureFlagSet(Constants.FLAG_XCHACHA);
    }

    /**
     * Returns true if content is encrypted with AES-SIV.
     *
     * @return true if AES-SIV is used
     */
    public boolean aessiv() {
        return isFeatureFlagSet(Constants.FLAG_AES_SIV);
    }

    /**
     * Returns the content-encryption cipher for the given key.
     *
     * @param key     the cipher key
     * @param xchacha whether to use XChaCha20-Poly1305 instead of AES-GCM
     * @return the content-encryption cipher
     */
    private static ContentCipher contentCipher(byte[] key, boolean xchacha) {
        return xchacha ? new XChaCha20Poly1305(key) : new Gcm(key);
    }

    /**
     * Returns the nonce/IV length in bytes for the content cipher.
     *
     * @return the nonce length in bytes
     */
    private int contentIvLen() {
        if (xchacha()) {
            return Constants.XCHACHA_NONCE_LEN;
        }
        return isFeatureFlagSet(Constants.FLAG_GCM_IV128) ? Constants.DEFAULT_IV_BITS / 8 : 96 / 8;
    }

    /**
     * Returns the HKDF info string for the given content cipher.
     *
     * @param xchacha whether the content cipher is XChaCha20-Poly1305
     * @return the HKDF info string
     */
    private static String contentHkdfInfo(boolean xchacha) {
        return xchacha ? Constants.HKDF_INFO_XCHACHA_CONTENT : Constants.HKDF_INFO_GCM_CONTENT;
    }

    /**
     * Builds the {@link ContentEnc} used for file-content crypto. The returned
     * instance shares no state with the config file.
     *
     * @param masterKey the 32-byte master key
     * @return the content-encryption helper
     * @throws NullPointerException if {@code masterKey} is {@code null}
     */
    public ContentEnc contentEnc(byte[] masterKey) {
        Objects.requireNonNull(masterKey, "masterKey");
        boolean useHkdf = hkdf();
        if (aessiv()) {
            byte[] sivKey = useHkdf
                    ? Hkdf.derive(masterKey, Constants.HKDF_INFO_SIV_CONTENT, Constants.SIV_KEY_LEN)
                    : sha512(masterKey);
            try {
                return new ContentEnc(new AesSiv(sivKey), Constants.AES_BLOCK_SIZE);
            } finally {
                Keys.wipe(sivKey);
            }
        }
        boolean xchacha = xchacha();
        byte[] contentKey = useHkdf
                ? Hkdf.derive(masterKey, contentHkdfInfo(xchacha), Constants.KEY_LEN)
                : Arrays.copyOf(masterKey, masterKey.length);
        try {
            return new ContentEnc(contentCipher(contentKey, xchacha), contentIvLen());
        } finally {
            Keys.wipe(contentKey);
        }
    }

    /**
     * Computes the SHA-512 digest of {@code data}, used as the AES-SIV key for
     * legacy (non-HKDF) filesystems.
     *
     * @param data the input data
     * @return the 64-byte SHA-512 digest
     */
    private static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-512 unavailable", e);
        }
    }

    /**
     * Creates a fresh config file with the given master key and password. The
     * resulting config uses HKDF, 128-bit GCM IVs, per-directory IVs, EME names,
     * long names and raw base64 (the modern gocryptfs defaults), or plaintext
     * names if {@code plaintextNames} is set.
     *
     * @param masterKey      the 32-byte master key
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @return the created config file
     */
    public static ConfigFile create(byte[] masterKey, char[] password, boolean plaintextNames) {
        return create(masterKey, password, plaintextNames, ContentCipherType.AES_GCM);
    }

    /**
     * Creates a fresh config file with the given master key and password. The
     * resulting config uses HKDF, per-directory IVs, EME names, long names and
     * raw base64 (the modern gocryptfs defaults), or plaintext names if
     * {@code plaintextNames} is set. Content encryption uses {@code cipherType}.
     *
     * @param masterKey      the 32-byte master key
     * @param password       the password to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @param cipherType     the content-encryption cipher
     * @return the created config file
     * @throws NullPointerException if {@code masterKey}, {@code password} or {@code cipherType} is {@code null}
     */
    public static ConfigFile create(byte[] masterKey, char[] password, boolean plaintextNames,
                                    ContentCipherType cipherType) {
        Objects.requireNonNull(password, "password");
        byte[] secret = charsToBytes(password);
        try {
            return create(masterKey, secret, plaintextNames, cipherType, null);
        } finally {
            Keys.wipe(secret);
        }
    }

    /**
     * Creates a fresh config file protected by a raw secret, optionally with
     * FIDO2 parameters.
     *
     * <p>This is the FIDO2 code path: {@code secret} is the raw bytes returned by
     * the token's {@code hmac-secret} extension and is used directly as the scrypt
     * password. When {@code fido2} is non-{@code null} the {@code FIDO2} feature
     * flag is set and the parameters are stored in the config.</p>
     *
     * @param masterKey      the 32-byte master key
     * @param secret         the raw secret to protect the master key with
     * @param plaintextNames whether to store file names unencrypted
     * @param cipherType     the content-encryption cipher
     * @param fido2          the FIDO2 parameters, or {@code null} for password protection
     * @return the created config file
     * @throws NullPointerException if {@code masterKey}, {@code secret} or {@code cipherType} is {@code null}
     */
    public static ConfigFile create(byte[] masterKey, byte[] secret, boolean plaintextNames,
                                    ContentCipherType cipherType, Fido2Params fido2) {
        Objects.requireNonNull(masterKey, "masterKey");
        Objects.requireNonNull(secret, "secret");
        Objects.requireNonNull(cipherType, "cipherType");
        ConfigFile cf = new ConfigFile();
        cf.creator = "gocryptfs4j 0.1";
        cf.version = Constants.CURRENT_VERSION;

        List<String> flags = new ArrayList<>();
        flags.add(Constants.FLAG_HKDF);
        switch (cipherType) {
            case XCHACHA20_POLY1305:
                flags.add(Constants.FLAG_XCHACHA);
                break;
            case AES_SIV:
                // gocryptfs rejects AESSIV configs without GCMIV128: AES-SIV uses
                // 128-bit IVs (the SIV), so both flags are required.
                flags.add(Constants.FLAG_AES_SIV);
                flags.add(Constants.FLAG_GCM_IV128);
                break;
            case AES_GCM:
            default:
                flags.add(Constants.FLAG_GCM_IV128);
                break;
        }
        if (plaintextNames) {
            flags.add(Constants.FLAG_PLAINTEXT_NAMES);
        } else {
            flags.add(Constants.FLAG_DIR_IV);
            flags.add(Constants.FLAG_EME_NAMES);
            flags.add(Constants.FLAG_LONG_NAMES);
            flags.add(Constants.FLAG_RAW64);
        }
        if (fido2 != null) {
            flags.add(Constants.FLAG_FIDO2);
        }
        cf.featureFlags = flags;
        cf.fido2 = fido2;

        ScryptKdf sk = new ScryptKdf();
        sk.salt = Base64.getEncoder().encodeToString(Keys.randomBytes(Constants.KEY_LEN));
        sk.n = 1 << 16;
        sk.r = 8;
        sk.p = 1;
        sk.keyLen = Constants.KEY_LEN;
        cf.scryptObject = sk;

        byte[] scryptHash = Keys.scrypt(
                secret, decode(sk.salt), sk.n, sk.r, sk.p, sk.keyLen);
        try {
            // The master key is always protected with AES-256-GCM; the content
            // cipher selection only affects file content.
            byte[] contentKey = Hkdf.derive(scryptHash, Constants.HKDF_INFO_GCM_CONTENT, Constants.KEY_LEN);
            byte[] nonce = Keys.randomBytes(Constants.DEFAULT_IV_BITS / 8);
            byte[] aad = new byte[8];
            byte[] ct = new Gcm(contentKey).encrypt(masterKey, nonce, aad);
            byte[] encrypted = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, encrypted, 0, nonce.length);
            System.arraycopy(ct, 0, encrypted, nonce.length, ct.length);
            cf.encryptedKey = Base64.getEncoder().encodeToString(encrypted);
        } finally {
            Keys.wipe(scryptHash);
        }
        return cf;
    }

    /**
     * Writes the config as JSON (with a trailing newline) to {@code path},
     * failing if the file already exists.
     *
     * @param path the path to write to
     * @throws IOException on filesystem errors, or if the file already exists
     * @throws NullPointerException if {@code path} is {@code null}
     */
    public void writeTo(Path path) throws IOException {
        writeTo(path, false);
    }

    /**
     * Writes the config as JSON (with a trailing newline) to {@code path},
     * optionally overwriting an existing file.
     *
     * @param path      the path to write to
     * @param overwrite whether to replace an existing file
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code path} is {@code null}
     */
    public void writeTo(Path path, boolean overwrite) throws IOException {
        Objects.requireNonNull(path, "path");
        String json = GSON.toJson(this) + "\n";
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        if (overwrite) {
            Files.write(path, bytes, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        } else {
            Files.write(path, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }
    }
}
