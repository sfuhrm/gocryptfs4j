package de.sfuhrm.gocryptfs4j.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Gcm;
import de.sfuhrm.gocryptfs4j.crypto.Hkdf;
import de.sfuhrm.gocryptfs4j.crypto.Keys;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Parses {@code gocryptfs.conf} and unlocks the master key from a password.
 */
public final class ConfigFile {

    private static final Gson GSON = new GsonBuilder().create();

    @SerializedName("Creator")
    public String creator;

    /** Base64-encoded encrypted master key. */
    @SerializedName("EncryptedKey")
    public String encryptedKey;

    @SerializedName("ScryptObject")
    public ScryptKdf scryptObject;

    @SerializedName("Version")
    public int version;

    @SerializedName("FeatureFlags")
    public List<String> featureFlags;

    @SerializedName("LongNameMax")
    public Integer longNameMax;

    @SerializedName("FIDO2")
    public Object fido2;

    private transient byte[] masterKey;

    public static ConfigFile load(Path path) throws IOException {
        String json = Files.readString(path, StandardCharsets.UTF_8);
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
        if (isFeatureFlagSet(Constants.FLAG_AES_SIV)) {
            throw new UnsupportedOperationException("AES-SIV content encryption is not supported");
        }
        if (isFeatureFlagSet(Constants.FLAG_XCHACHA)) {
            throw new UnsupportedOperationException("XChaCha20-Poly1305 content encryption is not supported");
        }
        if (isFeatureFlagSet(Constants.FLAG_FIDO2)) {
            throw new UnsupportedOperationException("FIDO2-based key protection is not supported");
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

    public boolean isFeatureFlagSet(String flag) {
        return featureFlags != null && featureFlags.contains(flag);
    }

    /**
     * Derives the scrypt key from the password and decrypts the master key.
     */
    public byte[] decryptMasterKey(char[] password) throws IOException {
        if (masterKey != null) {
            return masterKey;
        }
        ScryptKdf s = scryptObject;
        byte[] scryptHash = Keys.scrypt(
                charsToBytes(password), decode(s.salt), s.n, s.r, s.p, s.keyLen);
        try {
            boolean useHkdf = isFeatureFlagSet(Constants.FLAG_HKDF);
            int ivLen = useHkdf ? Constants.DEFAULT_IV_BITS / 8 : 96 / 8;
            byte[] gcmKey = useHkdf
                    ? Hkdf.derive(scryptHash, Constants.HKDF_INFO_GCM_CONTENT, Constants.KEY_LEN)
                    : scryptHash;

            byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKey);
            byte[] nonce = Arrays.copyOfRange(encryptedKeyBytes, 0, ivLen);
            byte[] ct = Arrays.copyOfRange(encryptedKeyBytes, ivLen, encryptedKeyBytes.length);
            // blockNo = 0, fileID = nil -> AAD is eight zero bytes
            byte[] aad = new byte[8];
            Gcm gcm = new Gcm(gcmKey);
            masterKey = gcm.decrypt(ct, nonce, aad);
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

    private static byte[] decode(String b64) {
        return Base64.getDecoder().decode(b64);
    }

    /** Returns true if file names are stored unencrypted. */
    public boolean plaintextNames() {
        return isFeatureFlagSet(Constants.FLAG_PLAINTEXT_NAMES);
    }

    /** Returns true if per-directory IVs are used for name encryption. */
    public boolean dirIv() {
        return isFeatureFlagSet(Constants.FLAG_DIR_IV);
    }

    /** Returns true if long file names may be hashed to {@code gocryptfs.longname.*}. */
    public boolean longNames() {
        return isFeatureFlagSet(Constants.FLAG_LONG_NAMES);
    }

    /** Returns the effective long-name limit (255 unless overridden). */
    public int longNameMax() {
        if (longNames() && longNameMax != null) {
            return longNameMax;
        }
        return Constants.NAME_MAX;
    }

    /** Returns true if file names use raw (unpadded) base64url. */
    public boolean raw64() {
        return isFeatureFlagSet(Constants.FLAG_RAW64);
    }

    /** Returns true if sub-keys are derived from the master key via HKDF. */
    public boolean hkdf() {
        return isFeatureFlagSet(Constants.FLAG_HKDF);
    }

    /**
     * Builds the {@link ContentEnc} used for file-content and master-key crypto.
     * The returned instance shares no state with the config file.
     */
    public ContentEnc contentEnc(byte[] masterKey) {
        boolean useHkdf = hkdf();
        int ivLen = useHkdf ? Constants.DEFAULT_IV_BITS / 8 : 96 / 8;
        byte[] gcmKey = useHkdf
                ? Hkdf.derive(masterKey, Constants.HKDF_INFO_GCM_CONTENT, Constants.KEY_LEN)
                : Arrays.copyOf(masterKey, masterKey.length);
        return new ContentEnc(gcmKey, ivLen);
    }

    /**
     * Creates a fresh config file with the given master key and password. The
     * resulting config uses HKDF, 128-bit GCM IVs, per-directory IVs, EME names,
     * long names and raw base64 (the modern gocryptfs defaults), or plaintext
     * names if {@code plaintextNames} is set.
     */
    public static ConfigFile create(byte[] masterKey, char[] password, boolean plaintextNames) {
        ConfigFile cf = new ConfigFile();
        cf.creator = "gocryptfs4j 0.1";
        cf.version = Constants.CURRENT_VERSION;

        List<String> flags = new ArrayList<>();
        flags.add(Constants.FLAG_HKDF);
        flags.add(Constants.FLAG_GCM_IV128);
        if (plaintextNames) {
            flags.add(Constants.FLAG_PLAINTEXT_NAMES);
        } else {
            flags.add(Constants.FLAG_DIR_IV);
            flags.add(Constants.FLAG_EME_NAMES);
            flags.add(Constants.FLAG_LONG_NAMES);
            flags.add(Constants.FLAG_RAW64);
        }
        cf.featureFlags = flags;

        ScryptKdf sk = new ScryptKdf();
        sk.salt = Base64.getEncoder().encodeToString(Keys.randomBytes(Constants.KEY_LEN));
        sk.n = 1 << 16;
        sk.r = 8;
        sk.p = 1;
        sk.keyLen = Constants.KEY_LEN;
        cf.scryptObject = sk;

        byte[] scryptHash = Keys.scrypt(
                charsToBytes(password), decode(sk.salt), sk.n, sk.r, sk.p, sk.keyLen);
        try {
            byte[] gcmKey = Hkdf.derive(scryptHash, Constants.HKDF_INFO_GCM_CONTENT, Constants.KEY_LEN);
            byte[] nonce = Keys.randomBytes(Constants.DEFAULT_IV_BITS / 8);
            byte[] aad = new byte[8];
            byte[] ct = new Gcm(gcmKey).encrypt(masterKey, nonce, aad);
            byte[] encrypted = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, encrypted, 0, nonce.length);
            System.arraycopy(ct, 0, encrypted, nonce.length, ct.length);
            cf.encryptedKey = Base64.getEncoder().encodeToString(encrypted);
        } finally {
            Keys.wipe(scryptHash);
        }
        return cf;
    }

    /** Writes the config as JSON (with a trailing newline) to {@code path}. */
    public void writeTo(Path path) throws IOException {
        String json = GSON.toJson(this) + "\n";
        Files.writeString(path, json, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
}
