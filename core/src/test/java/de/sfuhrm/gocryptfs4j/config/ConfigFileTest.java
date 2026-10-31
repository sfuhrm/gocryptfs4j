package de.sfuhrm.gocryptfs4j.config;

import com.google.gson.Gson;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.core.ContentCipherType;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigFileTest {

    private static final char[] PASSWORD = "secretpw".toCharArray();

    /** A dummy, well-formed encrypted key (nonce + key + tag) for configs that only test other fields. */
    private static final String VALID_ENCRYPTED_KEY =
            Base64.getEncoder().encodeToString(new byte[64]);

    @Test
    void createWithXchachaSetsFlag() {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.XCHACHA20_POLY1305);
        assertTrue(cf.xchacha());
        assertTrue(cf.featureFlags().contains(Constants.FLAG_XCHACHA));
        assertFalse(cf.featureFlags().contains(Constants.FLAG_GCM_IV128));
    }

    @Test
    void createWithAesSivSetsFlag() {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.AES_SIV);
        assertTrue(cf.aessiv());
        assertTrue(cf.featureFlags().contains(Constants.FLAG_AES_SIV));
        assertTrue(cf.featureFlags().contains(Constants.FLAG_GCM_IV128));
        assertFalse(cf.featureFlags().contains(Constants.FLAG_XCHACHA));
    }

    @Test
    void createWithGcmSetsGcmFlag() {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.AES_GCM);
        assertFalse(cf.xchacha());
        assertFalse(cf.aessiv());
        assertTrue(cf.featureFlags().contains(Constants.FLAG_GCM_IV128));
        assertFalse(cf.featureFlags().contains(Constants.FLAG_XCHACHA));
    }

    @Test
    void creatorCarriesProjectVersion() {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.AES_GCM);
        assertTrue(cf.creator().startsWith("gocryptfs4j "), cf.creator());
        assertTrue(cf.creator().matches("gocryptfs4j \\d+\\.\\d+.*"), cf.creator());
    }

    @ParameterizedTest
    @EnumSource(ContentCipherType.class)
    void masterKeyRoundTrip(ContentCipherType cipherType) throws Exception {
        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
        ConfigFile cf = ConfigFile.create(masterKey, PASSWORD, false, cipherType);

        assertArrayEquals(masterKey, cf.decryptMasterKey(PASSWORD));
    }

    @ParameterizedTest
    @EnumSource(ContentCipherType.class)
    void contentEncUsesConfiguredCipher(ContentCipherType cipherType) throws Exception {
        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
        ConfigFile cf = ConfigFile.create(masterKey, PASSWORD, false, cipherType);

        ContentEnc enc = cf.contentEnc(masterKey);
        int expectedIvLen;
        switch (cipherType) {
            case XCHACHA20_POLY1305:
                expectedIvLen = Constants.XCHACHA_NONCE_LEN;
                break;
            case AES_SIV:
            case AES_GCM:
            default:
                expectedIvLen = Constants.DEFAULT_IV_BITS / 8;
                break;
        }
        assertEquals(expectedIvLen, enc.ivLen);
        assertEquals(expectedIvLen + Constants.AUTH_TAG_LEN, enc.blockOverhead());

        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        byte[] data = new byte[1000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        byte[] ct = enc.encryptBlock(data, 0, fileId);
        assertArrayEquals(data, enc.decryptBlock(ct, 0, fileId));
    }

    @Test
    void wrongPasswordRejected() throws Exception {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.AES_SIV);
        assertTrue(cf.aessiv());
        try {
            cf.decryptMasterKey("wrong".toCharArray());
            org.junit.jupiter.api.Assertions.fail("expected IOException for wrong password");
        } catch (java.io.IOException expected) {
            // ok
        }
    }

    @Test
    void reencryptMasterKeyChangesPassword() throws Exception {
        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
        ConfigFile cf = ConfigFile.create(masterKey, PASSWORD, false, ContentCipherType.AES_GCM);

        cf.reencryptMasterKey(masterKey, "new-password".toCharArray());

        assertArrayEquals(masterKey, cf.decryptMasterKey("new-password".toCharArray()));

        // A freshly parsed config accepts the new and rejects the old password.
        ConfigFile reloaded = ConfigFile.fromBytes(cf.toBytes());
        assertArrayEquals(masterKey, reloaded.decryptMasterKey("new-password".toCharArray()));

        // The master key is not cached: the same instance still rejects
        // the old password.
        assertThrows(IOException.class, () -> reloaded.decryptMasterKey(PASSWORD));
    }

    @Test
    void reencryptMasterKeyRejectsWrongLength() {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.AES_GCM);
        assertThrows(IllegalArgumentException.class,
                () -> cf.reencryptMasterKey(new byte[16], "pw".toCharArray()));
    }

    @Test
    void reencryptMasterKeyRejectsFido2Config() {
        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
        Fido2Params fido2 = new Fido2Params(new byte[]{1, 2, 3}, new byte[32], null);
        ConfigFile cf = ConfigFile.create(masterKey, "secret".getBytes(StandardCharsets.UTF_8),
                false, ContentCipherType.AES_GCM, fido2);
        assertTrue(cf.isFeatureFlagSet(Constants.FLAG_FIDO2));
        assertThrows(IllegalStateException.class,
                () -> cf.reencryptMasterKey(masterKey, "new-pw".toCharArray()));
    }

    @Test
    void passwordIsEncodedAsUtf8() throws Exception {
        // German umlauts: UTF-8 is multi-byte and differs from low-byte truncation.
        String password = "Gr\u00fc\u00dfe-\u00d6l-\u00e4\u00f6\u00fc";
        byte[] utf8 = password.getBytes(StandardCharsets.UTF_8);
        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);

        // A config protected with the raw UTF-8 bytes (what gocryptfs reads
        // from a UTF-8 passfile) must unlock via the char[] API ...
        ConfigFile fromBytes = ConfigFile.create(masterKey, utf8, false,
                ContentCipherType.AES_GCM, null);
        assertArrayEquals(masterKey, fromBytes.decryptMasterKey(password.toCharArray()));

        // ... and the reverse: created from char[], unlocked with UTF-8 bytes.
        ConfigFile fromChars = ConfigFile.create(masterKey, password.toCharArray(), false,
                ContentCipherType.AES_GCM);
        assertArrayEquals(masterKey, fromChars.decryptMasterKey(utf8));

        // The former low-byte (Latin-1) interpretation must no longer unlock it.
        byte[] lowByte = new byte[password.length()];
        for (int i = 0; i < password.length(); i++) {
            lowByte[i] = (byte) password.charAt(i);
        }
        assertThrows(IOException.class, () -> fromBytes.decryptMasterKey(lowByte));
    }

    @Test
    void loadRejectsOutOfRangeScryptParameters() throws Exception {
        Path dir = Files.createTempDirectory("gocryptfs4j-");
        String salt32 = Base64.getEncoder().encodeToString(new byte[32]);
        String flags = "[\"HKDF\",\"GCMIV128\"]";
        try {
            // A normal gocryptfs parameter set loads fine.
            assertNotNull(ConfigFile.load(
                    writeConf(dir, salt32, 1 << 16, 8, 1, 32, flags, null)));

            // N too large, too small, or not a power of two.
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 30, 8, 1, 32, flags, null)));
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 9, 8, 1, 32, flags, null)));
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, (1 << 16) + 1, 8, 1, 32, flags, null)));
            // R and P too large.
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 16, 1 << 20, 1, 32, flags, null)));
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 16, 8, 1 << 20, 32, flags, null)));
            // KeyLen must be the 32 bytes gocryptfs uses.
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 16, 8, 1, 16, flags, null)));
            // 128 * N * R * P exceeding the cost bound (128 * 2^20 * 32 * 1 = 4 GiB).
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 20, 32, 1, 32, flags, null)));
            // N=2^20 with R=8 alone is 1 GiB and must now be rejected.
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 20, 8, 1, 32, flags, null)));
            // P now scales the bound: default N,R with P=16 reaches 1 GiB as well.
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 16, 8, 16, 32, flags, null)));
            // Salt too short / too long.
            String salt8 = Base64.getEncoder().encodeToString(new byte[8]);
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt8, 1 << 16, 8, 1, 32, flags, null)));
            String salt128 = Base64.getEncoder().encodeToString(new byte[128]);
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt128, 1 << 16, 8, 1, 32, flags, null)));
        } finally {
            Files.deleteIfExists(dir.resolve("gocryptfs.conf"));
            Files.deleteIfExists(dir);
        }
    }

    @Test
    void loadRejectsOversizedConfigFile() throws Exception {
        Path dir = Files.createTempDirectory("gocryptfs4j-");
        try {
            Path conf = dir.resolve("gocryptfs.conf");
            Files.write(conf, new byte[Constants.CONFIG_MAX_SIZE + 1]);

            IOException thrown = assertThrows(IOException.class,
                    () -> ConfigFile.load(new PathCipherStore(dir)));
            assertTrue(thrown.getMessage().contains("too large"), thrown.getMessage());
        } finally {
            Files.deleteIfExists(dir.resolve("gocryptfs.conf"));
            Files.deleteIfExists(dir);
        }
    }

    @Test
    void loadRejectsMalformedJson() throws Exception {
        Path dir = Files.createTempDirectory("gocryptfs4j-");
        try {
            Path conf = dir.resolve("gocryptfs.conf");
            Files.write(conf, "{not valid json".getBytes(StandardCharsets.UTF_8));
            assertThrows(IOException.class, () -> ConfigFile.load(new PathCipherStore(dir)));
        } finally {
            Files.deleteIfExists(dir.resolve("gocryptfs.conf"));
            Files.deleteIfExists(dir);
        }
    }

    @Test
    void loadRejectsInvalidEncryptedKey() throws Exception {
        Path dir = Files.createTempDirectory("gocryptfs4j-");
        try {
            assertThrows(IOException.class,
                    () -> ConfigFile.load(writeConfWithEncryptedKey(dir, "!!!not base64!!!")));
        } finally {
            Files.deleteIfExists(dir.resolve("gocryptfs.conf"));
            Files.deleteIfExists(dir);
        }
    }

    @Test
    void loadRejectsTooShortEncryptedKey() throws Exception {
        Path dir = Files.createTempDirectory("gocryptfs4j-");
        try {
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConfWithEncryptedKey(dir, Base64.getEncoder().encodeToString(new byte[4]))));
        } finally {
            Files.deleteIfExists(dir.resolve("gocryptfs.conf"));
            Files.deleteIfExists(dir);
        }
    }

    @Test
    void decryptMasterKeyRejectsMissingOrInvalidEncryptedKey() {
        assertThrows(IOException.class,
                () -> parseWithEncryptedKey(null).decryptMasterKey(PASSWORD));
        assertThrows(IOException.class,
                () -> parseWithEncryptedKey("!!!not base64!!!").decryptMasterKey(PASSWORD));
        assertThrows(IOException.class,
                () -> parseWithEncryptedKey(Base64.getEncoder().encodeToString(new byte[4]))
                        .decryptMasterKey(PASSWORD));
    }

    @Test
    void loadRejectsOverlongFido2Parameters() throws Exception {
        Path dir = Files.createTempDirectory("gocryptfs4j-");
        String salt32 = Base64.getEncoder().encodeToString(new byte[32]);
        String flags = "[\"HKDF\",\"GCMIV128\",\"FIDO2\"]";
        String goodSalt = Base64.getEncoder().encodeToString(new byte[32]);
        try {
            String hugeId = Base64.getEncoder().encodeToString(new byte[2048]);
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 16, 8, 1, 32, flags,
                            "{\"CredentialID\":\"" + hugeId + "\",\"HMACSalt\":\""
                                    + goodSalt + "\"}")));

            String shortId = Base64.getEncoder().encodeToString(new byte[16]);
            String hugeSalt = Base64.getEncoder().encodeToString(new byte[256]);
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 16, 8, 1, 32, flags,
                            "{\"CredentialID\":\"" + shortId + "\",\"HMACSalt\":\""
                                    + hugeSalt + "\"}")));

            // Too many assertion options.
            StringBuilder many = new StringBuilder("[");
            for (int i = 0; i < 100; i++) {
                if (i > 0) {
                    many.append(',');
                }
                many.append("\"o").append(i).append('"');
            }
            many.append(']');
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 16, 8, 1, 32, flags,
                            "{\"CredentialID\":\"" + shortId + "\",\"HMACSalt\":\""
                                    + goodSalt + "\",\"AssertOptions\":" + many + "}")));

            // A single overlong assertion option.
            StringBuilder longOption = new StringBuilder();
            for (int i = 0; i < 2048; i++) {
                longOption.append('x');
            }
            assertThrows(IOException.class, () -> ConfigFile.load(
                    writeConf(dir, salt32, 1 << 16, 8, 1, 32, flags,
                            "{\"CredentialID\":\"" + shortId + "\",\"HMACSalt\":\""
                                    + goodSalt + "\",\"AssertOptions\":[\"" + longOption + "\"]}")));
        } finally {
            Files.deleteIfExists(dir.resolve("gocryptfs.conf"));
            Files.deleteIfExists(dir);
        }
    }

    private static CipherStore writeConf(Path dir, String saltB64, int n, int r, int p, int keyLen,
                                         String featureFlags, String fido2) throws IOException {
        StringBuilder json = new StringBuilder();
        json.append("{\"Creator\":\"test\",\"EncryptedKey\":\"").append(VALID_ENCRYPTED_KEY).append("\",");
        json.append("\"ScryptObject\":{\"Salt\":\"").append(saltB64).append("\",");
        json.append("\"N\":").append(n).append(",\"R\":").append(r)
                .append(",\"P\":").append(p).append(",\"KeyLen\":").append(keyLen).append("},");
        json.append("\"Version\":2,\"FeatureFlags\":").append(featureFlags);
        if (fido2 != null) {
            json.append(",\"FIDO2\":").append(fido2);
        }
        json.append('}');
        Path conf = dir.resolve("gocryptfs.conf");
        Files.write(conf, json.toString().getBytes(StandardCharsets.UTF_8));
        return new PathCipherStore(dir);
    }

    private static CipherStore writeConfWithEncryptedKey(Path dir, String encryptedKeyB64)
            throws IOException {
        Path conf = dir.resolve("gocryptfs.conf");
        Files.write(conf, confJsonWithEncryptedKey(encryptedKeyB64).getBytes(StandardCharsets.UTF_8));
        return new PathCipherStore(dir);
    }

    /**
     * Builds a {@link ConfigFile} directly with Gson (bypassing {@code load()}'s
     * validation) with the given encrypted key, or without an encrypted key when
     * {@code null}. The scrypt object is valid so that only the encrypted key is
     * the problem.
     */
    private static ConfigFile parseWithEncryptedKey(String encryptedKeyB64) {
        return new Gson().fromJson(confJsonWithEncryptedKey(encryptedKeyB64), ConfigFile.class);
    }

    private static String confJsonWithEncryptedKey(String encryptedKeyB64) {
        String salt32 = Base64.getEncoder().encodeToString(new byte[32]);
        StringBuilder json = new StringBuilder();
        json.append("{\"Creator\":\"test\",");
        if (encryptedKeyB64 != null) {
            json.append("\"EncryptedKey\":\"").append(encryptedKeyB64).append("\",");
        }
        json.append("\"ScryptObject\":{\"Salt\":\"").append(salt32).append("\",");
        json.append("\"N\":").append(1 << 16).append(",\"R\":8,\"P\":1,\"KeyLen\":32},");
        json.append("\"Version\":2,\"FeatureFlags\":[\"HKDF\",\"GCMIV128\"]}");
        return json.toString();
    }
}
