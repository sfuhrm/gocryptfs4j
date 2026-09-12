package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.config.ConfigFile;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GocryptFsFido2Test {

    @TempDir
    Path tmp;

    @Test
    void createAndReopenWithFido2Token() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        Fido2Token token = new FakeToken("seed-a".getBytes(StandardCharsets.UTF_8));

        byte[] content = "fido2 secret".getBytes(StandardCharsets.UTF_8);
        try (GocryptFs fs = GocryptFs.create(cipherDir, token)) {
            fs.createFile("/hello.txt");
            fs.write("/hello.txt", 0, content);
            assertArrayEquals(content, fs.readAll("/hello.txt"));
        }

        try (GocryptFs fs = GocryptFs.open(cipherDir, token)) {
            assertArrayEquals(content, fs.readAll("/hello.txt"));
        }
    }

    @Test
    void configStoresBase64Fido2Object() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        FakeToken token = new FakeToken("seed-b".getBytes(StandardCharsets.UTF_8));

        try (GocryptFs ignored = GocryptFs.create(cipherDir, token)) {
            // just create
        }

        String json = new String(Files.readAllBytes(
                cipherDir.resolve(Constants.CONF_DEFAULT_NAME)), StandardCharsets.UTF_8);
        assertTrue(json.contains("\"FIDO2\""), json);
        assertTrue(json.contains("\"CredentialID\""), json);
        assertTrue(json.contains("\"HMACSalt\""), json);
        assertTrue(json.contains(Constants.FLAG_FIDO2), json);

        ConfigFile config = ConfigFile.load(cipherDir.resolve(Constants.CONF_DEFAULT_NAME));
        assertTrue(config.isFeatureFlagSet(Constants.FLAG_FIDO2));
        assertNotNull(config.fido2);
        assertEquals(32, config.fido2.hmacSalt.length);
        assertArrayEquals(token.lastCredentialId, config.fido2.credentialId);
        // The credential ID must be stored as a standard base64 string, not as a
        // JSON number array (Gson's default for byte[]). Gson escapes the base64
        // padding '=' as "\u003d".
        String encoded = Base64.getEncoder().encodeToString(token.lastCredentialId);
        assertTrue(json.contains(encoded.replace("=", "\\u003d")), json);
    }

    @Test
    void openWithDifferentTokenFails() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        Fido2Token token = new FakeToken("seed-c".getBytes(StandardCharsets.UTF_8));

        try (GocryptFs ignored = GocryptFs.create(cipherDir, token)) {
            // just create
        }

        Fido2Token other = new FakeToken("seed-d".getBytes(StandardCharsets.UTF_8));
        IOException e = assertThrows(IOException.class, () -> GocryptFs.open(cipherDir, other));
        assertTrue(e.getMessage().contains("FIDO2"), e.getMessage());
    }

    @Test
    void openPasswordCreatedFilesystemWithTokenIsRejected() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs ignored = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // just create
        }

        Fido2Token token = new FakeToken("seed-e".getBytes(StandardCharsets.UTF_8));
        assertThrows(IOException.class, () -> GocryptFs.open(cipherDir, token));
    }

    @Test
    void createWithOptionsAndCipherStoresThem() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        Fido2Token token = new FakeToken("seed-f".getBytes(StandardCharsets.UTF_8));

        try (GocryptFs fs = GocryptFs.create(cipherDir, token, "my-user", false,
                ContentCipherType.XCHACHA20_POLY1305, Collections.singletonList("uv=1"))) {
            fs.createFile("/a");
            fs.write("/a", 0, new byte[]{1, 2, 3});
        }

        ConfigFile config = ConfigFile.load(cipherDir.resolve(Constants.CONF_DEFAULT_NAME));
        assertTrue(config.xchacha());
        assertEquals(Collections.singletonList("uv=1"), config.fido2.assertOptions);

        try (GocryptFs fs = GocryptFs.open(cipherDir, token)) {
            assertArrayEquals(new byte[]{1, 2, 3}, fs.readAll("/a"));
        }
    }

    /** Deterministic fake token: the HMAC secret only depends on the seed and the inputs. */
    private static final class FakeToken implements Fido2Token {

        private final byte[] seed;
        private byte[] lastCredentialId;

        FakeToken(byte[] seed) {
            this.seed = seed;
        }

        @Override
        public byte[] registerCredential(String userName) throws IOException {
            lastCredentialId = hmac(userName.getBytes(StandardCharsets.UTF_8));
            return lastCredentialId.clone();
        }

        @Override
        public byte[] hmacSecret(byte[] credentialId, byte[] hmacSalt, List<String> assertOptions)
                throws IOException {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(seed, "HmacSHA256"));
                mac.update(credentialId);
                mac.update(hmacSalt);
                return mac.doFinal();
            } catch (java.security.GeneralSecurityException e) {
                throw new IOException(e);
            }
        }

        private byte[] hmac(byte[] input) throws IOException {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(seed, "HmacSHA256"));
                return mac.doFinal(input);
            } catch (java.security.GeneralSecurityException e) {
                throw new IOException(e);
            }
        }
    }
}
