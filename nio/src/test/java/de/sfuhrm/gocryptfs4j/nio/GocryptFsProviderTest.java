package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class GocryptFsProviderTest {

    @TempDir
    Path tmp;

    @Test
    void nioTraversal() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.mkdir("/a");
            fs.createFile("/a/one.txt");
            fs.write("/a/one.txt", 0, "one".getBytes(StandardCharsets.UTF_8));
        }

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, "pw".toCharArray())) {
            Path root = nio.getPath("/");
            assertEquals("/", root.toString());

            // Directory traversal
            Set<String> names = new HashSet<>();
            try (DirectoryStream<Path> ds = provider.newDirectoryStream(root, null)) {
                for (Path p : ds) {
                    names.add(p.getFileName().toString());
                }
            }
            assertEquals(Collections.singleton("a"), names);

            Path one = nio.getPath("/a/one.txt");
            assertArrayEquals("one".getBytes(StandardCharsets.UTF_8),
                    Files.readAllBytes(one));
        }
    }

    @Test
    void nioReadWriteViaFilesApi() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.mkdir("/data");
        }

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, "pw".toCharArray())) {
            Path file = nio.getPath("/data/numbers.bin");
            byte[] data = new byte[12345];
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) (i & 0xFF);
            }
            Files.write(file, data);
            assertArrayEquals(data, Files.readAllBytes(file));
            assertEquals(data.length, Files.size(file));

            Path sub = nio.getPath("/data/sub");
            Files.createDirectory(sub);
            Files.write(sub.resolve("x.txt"), "x".getBytes(StandardCharsets.UTF_8));
            assertEquals("x", new String(Files.readAllBytes(sub.resolve("x.txt")), StandardCharsets.UTF_8));

            Files.delete(file);
            assertFalse(Files.exists(file));
        }
    }

    @Test
    void nioOpensFido2Filesystem() throws IOException {
        Path cipherDir = tmp.resolve("cipher-fido2");
        Files.createDirectory(cipherDir);
        Fido2Token token = new FakeToken("nio-seed".getBytes(StandardCharsets.UTF_8));

        try (GocryptFs fs = GocryptFs.create(cipherDir, token)) {
            fs.createFile("/secret.txt");
            fs.write("/secret.txt", 0, "secret".getBytes(StandardCharsets.UTF_8));
        }

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, token)) {
            assertEquals("secret", new String(
                    Files.readAllBytes(nio.getPath("/secret.txt")), StandardCharsets.UTF_8));
        }
    }

    @Test
    void nioOpensFido2FilesystemViaUriEnvironment() throws IOException {
        Path cipherDir = tmp.resolve("cipher-fido2-uri");
        Files.createDirectory(cipherDir);
        Fido2Token token = new FakeToken("nio-seed-2".getBytes(StandardCharsets.UTF_8));

        try (GocryptFs fs = GocryptFs.create(cipherDir, token)) {
            fs.createFile("/a.txt");
            fs.write("/a.txt", 0, "a".getBytes(StandardCharsets.UTF_8));
        }

        Map<String, Object> env = new HashMap<>();
        env.put("cipherDir", cipherDir);
        env.put("fido2Token", token);

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(URI.create("gocryptfs:///"), env)) {
            assertEquals("a", new String(
                    Files.readAllBytes(nio.getPath("/a.txt")), StandardCharsets.UTF_8));
        }
    }

    @Test
    void nioRejectsPasswordAndTokenTogether() throws IOException {
        Path cipherDir = tmp.resolve("cipher-both");
        Files.createDirectory(cipherDir);
        Fido2Token token = new FakeToken("nio-seed-3".getBytes(StandardCharsets.UTF_8));

        Map<String, Object> env = new HashMap<>();
        env.put("cipherDir", cipherDir);
        env.put("password", "pw".toCharArray());
        env.put("fido2Token", token);

        GocryptFsProvider provider = new GocryptFsProvider();
        assertThrows(IllegalArgumentException.class,
                () -> provider.newFileSystem(URI.create("gocryptfs:///"), env));
    }

    @Test
    void nioRejectsAlreadyOpenFilesystem() throws IOException {
        Path cipherDir = tmp.resolve("cipher-open");
        Files.createDirectory(cipherDir);
        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // just create
        }

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem first = provider.newFileSystem(cipherDir, "pw".toCharArray())) {
            assertNotNull(first);
            assertThrows(FileSystemAlreadyExistsException.class,
                    () -> provider.newFileSystem(cipherDir, "pw".toCharArray()));
        }
        // After closing, the same directory can be opened again.
        try (FileSystem reopened = provider.newFileSystem(cipherDir, "pw".toCharArray())) {
            assertNotNull(reopened);
        }
    }

    @Test
    void uriLookupRoundTrip() throws IOException {
        Path cipherDir = tmp.resolve("cipher-uri");
        Files.createDirectory(cipherDir);
        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // just create
        }

        GocryptFsProvider provider = new GocryptFsProvider();
        Map<String, Object> env = new HashMap<>();
        env.put("cipherDir", cipherDir);
        env.put("password", "pw".toCharArray());
        try (FileSystem nio = provider.newFileSystem(URI.create("gocryptfs:///"), env)) {
            URI uri = nio.getPath("/a/b").toUri();
            assertSame(nio, provider.getFileSystem(uri));
            assertEquals("/a/b", provider.getPath(uri).toString());
            assertEquals("/", provider.getPath(URI.create(nio.toString().replaceAll("/$", "")))
                    .toString());
        }
        assertThrows(FileSystemNotFoundException.class,
                () -> provider.getFileSystem(URI.create("gocryptfs://missing/")));
    }

    @Test
    void uriValidation() {
        GocryptFsProvider provider = new GocryptFsProvider();
        assertEquals("gocryptfs", provider.getScheme());

        Map<String, Object> env = new HashMap<>();
        assertThrows(IllegalArgumentException.class,
                () -> provider.newFileSystem(URI.create("other:///"), env));
        assertThrows(IllegalArgumentException.class,
                () -> provider.newFileSystem(URI.create("gocryptfs:///"), env));

        env.put("cipherDir", tmp);
        assertThrows(IllegalArgumentException.class,
                () -> provider.newFileSystem(URI.create("gocryptfs:///"), env));

        env.put("password", "not-a-char-array");
        assertThrows(IllegalArgumentException.class,
                () -> provider.newFileSystem(URI.create("gocryptfs:///"), env));

        env.remove("password");
        env.put("fido2Token", "not-a-token");
        assertThrows(IllegalArgumentException.class,
                () -> provider.newFileSystem(URI.create("gocryptfs:///"), env));

        assertThrows(FileSystemNotFoundException.class,
                () -> provider.getFileSystem(URI.create("gocryptfs:///")));
        assertThrows(IllegalArgumentException.class,
                () -> provider.newDirectoryStream(Paths.get("/tmp"), null));
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
