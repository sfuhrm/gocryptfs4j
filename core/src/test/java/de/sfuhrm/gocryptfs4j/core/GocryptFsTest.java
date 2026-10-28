package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.config.ConfigFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class GocryptFsTest {

    @TempDir
    Path tmp;

    @Test
    void openWithMasterKey() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/hello.txt");
            fs.write("/hello.txt", 0, "secret".getBytes(StandardCharsets.UTF_8));
        }

        byte[] masterKey = ConfigFile.load(cipherDir.resolve("gocryptfs.conf"))
                .decryptMasterKey("pw".toCharArray());

        try (GocryptFs fs = GocryptFs.open(cipherDir, masterKey)) {
            assertEquals("secret", new String(fs.readAll("/hello.txt"), StandardCharsets.UTF_8));
        }
    }

    @Test
    void openWithWrongLengthMasterKeyThrows() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // just create the filesystem
        }

        assertThrows(IllegalArgumentException.class,
                () -> GocryptFs.open(cipherDir, new byte[16]));
    }

    @Test
    void openDoesNotModifyCallerMasterKeyArray() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // just create the filesystem
        }

        byte[] masterKey = ConfigFile.load(cipherDir.resolve("gocryptfs.conf"))
                .decryptMasterKey("pw".toCharArray());
        byte[] before = masterKey.clone();

        try (GocryptFs fs = GocryptFs.open(cipherDir, masterKey)) {
            fs.list("/");
        }

        assertArrayEquals(before, masterKey,
                "the caller's master-key array must be neither retained nor wiped");
    }

    @Test
    void openAndCreateDoNotModifyCallerPassword() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        char[] createPassword = "pw".toCharArray();
        char[] createBefore = createPassword.clone();
        try (GocryptFs fs = GocryptFs.create(cipherDir, createPassword)) {
            fs.list("/");
        }
        assertArrayEquals(createBefore, createPassword,
                "the caller's password must be neither retained nor wiped");

        char[] openPassword = "pw".toCharArray();
        char[] openBefore = openPassword.clone();
        try (GocryptFs fs = GocryptFs.open(cipherDir, openPassword)) {
            fs.list("/");
        }
        assertArrayEquals(openBefore, openPassword,
                "the caller's password must be neither retained nor wiped");
    }

    @Test
    void closeInvalidatesCryptoState() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray());
        fs.createFile("/f.txt");
        fs.write("/f.txt", 0, "data".getBytes(StandardCharsets.UTF_8));
        fs.close();

        assertThrows(IllegalStateException.class, () -> fs.readAll("/f.txt"));
        assertThrows(IllegalStateException.class,
                () -> fs.write("/f.txt", 0, new byte[]{1}));
    }

    @Test
    void constructorAbortWipesMasterKey() throws Exception {
        // A non-HKDF config with a short master key makes the constructor fail
        // while deriving the EME key, after the master key was handed over. A
        // freshly constructed ConfigFile has no feature flags, so HKDF is off.
        ConfigFile config = new ConfigFile();
        byte[] masterKey = new byte[16];
        Arrays.fill(masterKey, (byte) 0x5a);

        Constructor<GocryptFs> constructor = GocryptFs.class.getDeclaredConstructor(
                Path.class, ConfigFile.class, byte[].class);
        constructor.setAccessible(true);

        InvocationTargetException thrown = assertThrows(InvocationTargetException.class,
                () -> constructor.newInstance(tmp, config, masterKey));

        assertInstanceOf(IllegalArgumentException.class, thrown.getCause());
        assertArrayEquals(new byte[16], masterKey,
                "master key must be wiped when construction aborts");
    }

    @Test
    void createWriteReadListAndReopen() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] secret = "hello gocryptfs".getBytes(StandardCharsets.UTF_8);
        byte[] big = new byte[100_000];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) (i * 31);
        }

        try (GocryptFs fs = GocryptFs.create(cipherDir, "secretpw".toCharArray())) {
            fs.mkdir("/docs");
            fs.createFile("/docs/hello.txt");
            fs.write("/docs/hello.txt", 0, secret);
            fs.createFile("/big.bin");
            fs.write("/big.bin", 0, big);

            // verify content via readAll
            assertArrayEquals(secret, fs.readAll("/docs/hello.txt"));
            assertArrayEquals(big, fs.readAll("/big.bin"));

            // verify listing
            Set<String> root = fs.list("/").stream()
                    .map(DirEntry::plainName).collect(Collectors.toSet());
            assertEquals(new HashSet<>(Arrays.asList("docs", "big.bin")), root);

            Set<String> docs = fs.list("/docs").stream()
                    .map(DirEntry::plainName).collect(Collectors.toSet());
            assertEquals(new HashSet<>(Arrays.asList("hello.txt")), docs);

            // verify size
            assertEquals(secret.length, fs.size("/docs/hello.txt"));
            assertEquals(big.length, fs.size("/big.bin"));
        }

        // Reopen and verify everything persists.
        try (GocryptFs fs = GocryptFs.open(cipherDir, "secretpw".toCharArray())) {
            assertArrayEquals(secret, fs.readAll("/docs/hello.txt"));
            assertArrayEquals(big, fs.readAll("/big.bin"));
            assertTrue(fs.list("/").stream().anyMatch(e -> e.plainName().equals("docs")));
        }

        // Wrong password must fail.
        assertThrows(IOException.class, () -> GocryptFs.open(cipherDir, "wrong".toCharArray()));
    }

    @Test
    void changePasswordReencryptsAndWritesAtomically() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] secret = "hello gocryptfs".getBytes(StandardCharsets.UTF_8);
        char[] oldPassword = "old-password".toCharArray();
        char[] newPassword = "new-password".toCharArray();

        try (GocryptFs fs = GocryptFs.create(cipherDir, oldPassword)) {
            fs.createFile("/hello.txt");
            fs.write("/hello.txt", 0, secret);

            fs.changePassword(newPassword);

            // The filesystem is still usable after the change, and the config
            // on disk was rewritten (atomically) in place.
            assertArrayEquals(secret, fs.readAll("/hello.txt"));
        }

        try (GocryptFs fs = GocryptFs.open(cipherDir, newPassword)) {
            assertArrayEquals(secret, fs.readAll("/hello.txt"));
        }
        assertThrows(IOException.class, () -> GocryptFs.open(cipherDir, oldPassword));
    }

    @Test
    void openWriteStreaming() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] data = new byte[250_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 17);
        }

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/stream.bin");
            try (OutputStream out = fs.openWrite("/stream.bin")) {
                for (int off = 0; off < data.length; off += 4096) {
                    int len = Math.min(4096, data.length - off);
                    out.write(data, off, len);
                }
            }
            assertArrayEquals(data, fs.readAll("/stream.bin"));
        }

        // Reopen and verify the streamed content persisted.
        try (GocryptFs fs = GocryptFs.open(cipherDir, "pw".toCharArray())) {
            assertArrayEquals(data, fs.readAll("/stream.bin"));
        }
    }

    @Test
    void writeLargeFileLoopsOverShortWrites() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] data = new byte[256 * 1024 * 2 + 123];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 29);
        }

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/large.bin");
            fs.write("/large.bin", 0, data);
            assertArrayEquals(data, fs.readAll("/large.bin"));
        }
    }

    @Test
    void openWriteOverwritesExistingContent() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/f.txt");
            fs.write("/f.txt", 0, "old content longer".getBytes(StandardCharsets.UTF_8));

            try (OutputStream out = fs.openWrite("/f.txt")) {
                out.write("new".getBytes(StandardCharsets.UTF_8));
            }

            // openWrite starts at offset 0 and truncates any previous content.
            assertEquals("new",
                    new String(fs.readAll("/f.txt"), StandardCharsets.UTF_8));
        }
    }

    @Test
    void openReadStreamsMultiBlockContent() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] data = new byte[250_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 23);
        }

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/stream.bin");
            fs.write("/stream.bin", 0, data);

            try (InputStream in = fs.openRead("/stream.bin")) {
                ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
                assertArrayEquals(data, out.toByteArray());
            }
        }
    }

    @Test
    void openReadByteByByteAndEof() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] data = "the quick brown fox".getBytes(StandardCharsets.UTF_8);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/text.txt");
            fs.write("/text.txt", 0, data);

            try (InputStream in = fs.openRead("/text.txt")) {
                for (byte expected : data) {
                    assertEquals(expected & 0xFF, in.read());
                }
                assertEquals(-1, in.read(), "read() past EOF must return -1");
            }
        }
    }

    @Test
    void openReadChunkedAcrossBlockBoundaries() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] data = new byte[50_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 5);
        }

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/chunk.bin");
            fs.write("/chunk.bin", 0, data);

            try (InputStream in = fs.openRead("/chunk.bin")) {
                ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);
                byte[] buf = new byte[7];
                int n;
                while ((n = in.read(buf, 0, buf.length)) != -1) {
                    out.write(buf, 0, n);
                }
                assertArrayEquals(data, out.toByteArray());
            }
        }
    }

    @Test
    void openReadMissingFileThrows() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            assertThrows(java.nio.file.NoSuchFileException.class,
                    () -> fs.openRead("/does-not-exist"));
        }
    }

    @Test
    void plaintextNamesRejectsControlFilePath() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        Path conf = cipherDir.resolve("gocryptfs.conf");

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray(), true)) {
            byte[] before = Files.readAllBytes(conf);

            // The root listing hides the control file ...
            assertTrue(fs.list("/").stream()
                    .noneMatch(e -> e.plainName().equals("gocryptfs.conf")));

            // ... and the path-based APIs must refuse to touch it.
            assertThrows(IllegalArgumentException.class, () -> fs.readAll("/gocryptfs.conf"));
            assertThrows(IllegalArgumentException.class,
                    () -> fs.write("/gocryptfs.conf", 0, new byte[]{1}));
            assertThrows(IllegalArgumentException.class, () -> fs.delete("/gocryptfs.conf"));
            assertThrows(IllegalArgumentException.class, () -> fs.createFile("/gocryptfs.conf"));
            assertThrows(IllegalArgumentException.class, () -> fs.mkdir("/gocryptfs.conf"));
            assertThrows(IllegalArgumentException.class, () -> fs.list("/gocryptfs.conf"));
            assertThrows(IllegalArgumentException.class, () -> fs.openRead("/gocryptfs.conf"));

            // The control file is untouched.
            assertArrayEquals(before, Files.readAllBytes(conf));

            // A same-named entry below the root is an ordinary file.
            fs.mkdir("/sub");
            fs.createFile("/sub/gocryptfs.conf");
            assertTrue(fs.list("/sub").stream()
                    .anyMatch(e -> e.plainName().equals("gocryptfs.conf")));
        }
    }

    @Test
    void resolveDoesNotFollowSymlinkOutOfRoot() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        Path target = Files.createTempDirectory("gocryptfs-symlink-target");

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray(), true)) {
            fs.createSymlink("/l", target.toString());

            // Traversing the symlink as an intermediate component must be
            // rejected rather than followed, so nothing is written outside.
            assertThrows(NotDirectoryException.class, () -> fs.mkdir("/l/x"));
            assertThrows(NotDirectoryException.class, () -> fs.createFile("/l/x"));
            assertFalse(Files.exists(target.resolve("x")),
                    "must not write outside the cipher root");
        } finally {
            Files.deleteIfExists(target);
        }
    }

    @Test
    void longFileNames() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 220; i++) {
            longName.append('x');
        }
        String name = longName.toString();

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/" + name);
            fs.write("/" + name, 0, "longname content".getBytes(StandardCharsets.UTF_8));

            List<String> names = fs.list("/").stream()
                    .map(DirEntry::plainName).collect(Collectors.toList());
            assertTrue(names.contains(name), "long name should be listed");

            assertEquals("longname content",
                    new String(fs.readAll("/" + name), StandardCharsets.UTF_8));
        }

        try (GocryptFs fs = GocryptFs.open(cipherDir, "pw".toCharArray())) {
            assertEquals("longname content",
                    new String(fs.readAll("/" + name), StandardCharsets.UTF_8));
        }
    }

    @Test
    void renameFileKeepsContentAndDirectoryMoveKeepsSubtree() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/a.txt");
            fs.write("/a.txt", 0, "data".getBytes(StandardCharsets.UTF_8));
            fs.mkdir("/d1");
            fs.mkdir("/d2");
            fs.mkdir("/d1/sub");
            fs.createFile("/d1/sub/f.txt");
            fs.write("/d1/sub/f.txt", 0, "deep".getBytes(StandardCharsets.UTF_8));

            Path oldCipher = fs.resolve("/a.txt").cipherPath;
            fs.rename("/a.txt", "/d2/b.txt", false);
            assertFalse(Files.exists(oldCipher, LinkOption.NOFOLLOW_LINKS));
            assertEquals("data", new String(fs.readAll("/d2/b.txt"), StandardCharsets.UTF_8));

            Path dirCipher = fs.resolve("/d1").cipherPath;
            fs.rename("/d1", "/d2/moved", false);
            assertFalse(Files.exists(dirCipher, LinkOption.NOFOLLOW_LINKS));
            assertEquals("deep", new String(
                    fs.readAll("/d2/moved/sub/f.txt"), StandardCharsets.UTF_8));
        }
    }

    @Test
    void renameLongNamesMoveSupportFile() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            sb.append('x');
        }
        String longA = sb + "A";
        String longB = sb + "B";
        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/" + longA);
            fs.mkdir("/dir");
            Path oldCipher = fs.resolve("/" + longA).cipherPath;
            Path oldName = oldCipher.resolveSibling(oldCipher.getFileName() + ".name");
            assertTrue(Files.exists(oldName));

            fs.rename("/" + longA, "/dir/" + longB, false);

            assertFalse(Files.exists(oldCipher, LinkOption.NOFOLLOW_LINKS));
            assertFalse(Files.exists(oldName), "old long-name file must be removed");
            Path newCipher = fs.resolve("/dir/" + longB).cipherPath;
            assertTrue(Files.exists(newCipher));
            assertTrue(Files.exists(newCipher.resolveSibling(newCipher.getFileName() + ".name")));
            assertEquals(1, fs.list("/dir").size());
            assertEquals(longB, fs.list("/dir").get(0).plainName());
        }
    }

    @Test
    void renameExistingTargetAndErrors() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);
        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/a");
            fs.write("/a", 0, "A".getBytes(StandardCharsets.UTF_8));
            fs.createFile("/b");
            fs.mkdir("/full");
            fs.createFile("/full/x");
            fs.mkdir("/empty");

            assertThrows(FileAlreadyExistsException.class, () -> fs.rename("/a", "/b", false));
            assertThrows(NoSuchFileException.class, () -> fs.rename("/missing", "/z", false));
            assertThrows(IOException.class, () -> fs.rename("/a", "/nodir/z", false));
            assertThrows(DirectoryNotEmptyException.class, () -> fs.rename("/a", "/full", true));
            assertThrows(IOException.class, () -> fs.rename("/full", "/full/in", false));
            assertTrue(fs.list("/").stream().anyMatch(e -> e.plainName().equals("a")));

            fs.rename("/a", "/b", true);
            assertEquals("A", new String(fs.readAll("/b"), StandardCharsets.UTF_8));
            fs.rename("/b", "/empty", true);
            assertEquals("A", new String(fs.readAll("/empty"), StandardCharsets.UTF_8));
            fs.rename("/empty", "/empty", false);
        }
    }

    @Test
    void deleteNonEmptyDirectoryKeepsDirIV() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.mkdir("/dir");
            fs.createFile("/dir/keep.txt");

            Path cipherPath = fs.resolve("/dir").cipherPath;
            Path dirIV = cipherPath.resolve("gocryptfs.diriv");
            assertTrue(Files.exists(dirIV), "a fresh directory has a gocryptfs.diriv");

            assertThrows(DirectoryNotEmptyException.class, () -> fs.delete("/dir"));

            assertTrue(Files.exists(dirIV),
                    "a rejected delete must not remove gocryptfs.diriv");
            assertTrue(Files.isDirectory(cipherPath, LinkOption.NOFOLLOW_LINKS),
                    "a rejected delete must not remove the directory");

            // Once empty, the directory (and its diriv) can be removed.
            fs.delete("/dir/keep.txt");
            fs.delete("/dir");
            assertFalse(Files.exists(cipherPath, LinkOption.NOFOLLOW_LINKS));
        }
    }

    @Test
    void deleteLongNamedDirectoryRemovesNameFile() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 220; i++) {
            longName.append('x');
        }
        String name = longName.toString();

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.mkdir("/" + name);

            GocryptFs.Resolved r = fs.resolve("/" + name);
            Path cipherPath = r.cipherPath;
            Path nameFile = cipherPath.resolveSibling(r.cipherName + ".name");
            assertTrue(Files.exists(nameFile), "long directories use a .name support file");

            fs.delete("/" + name);

            assertFalse(Files.exists(cipherPath, LinkOption.NOFOLLOW_LINKS));
            assertFalse(Files.exists(nameFile), "the .name support file must be removed");
        }
    }

    @Test
    void cipherInputStreamWipesReadAheadBufferOnClose() throws Exception {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/f.txt");
            fs.write("/f.txt", 0, "secret plaintext".getBytes(StandardCharsets.UTF_8));

            InputStream in = fs.openRead("/f.txt");
            // A single-byte read populates the read-ahead buffer.
            assertTrue(in.read() >= 0);

            Field bufField = in.getClass().getDeclaredField("buf");
            bufField.setAccessible(true);
            byte[] buf = (byte[]) bufField.get(in);
            boolean nonZero = false;
            for (byte b : buf) {
                if (b != 0) {
                    nonZero = true;
                    break;
                }
            }
            assertTrue(nonZero, "the read-ahead buffer should hold plaintext before close");

            in.close();

            for (byte b : (byte[]) bufField.get(in)) {
                assertEquals(0, b, "the read-ahead buffer must be wiped on close");
            }
        }
    }

    @Test
    void oversizedDirIVRejected() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            // A gocryptfs.diriv is exactly 16 bytes; a larger one must be
            // rejected without being buffered in full.
            Files.write(cipherDir.resolve("gocryptfs.diriv"), new byte[4096]);
            assertThrows(IOException.class, () -> fs.list("/"));
        }
    }

    @Test
    void nameTooLongRejected() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 256; i++) {
            sb.append('x');
        }
        String tooLong = sb.toString();

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            FileSystemException e = assertThrows(FileSystemException.class,
                    () -> fs.createFile("/" + tooLong));
            assertTrue(e.getMessage().contains("File name too long"), e.getMessage());
            assertThrows(FileSystemException.class, () -> fs.mkdir("/" + tooLong));
            assertThrows(FileSystemException.class, () -> fs.createSymlink("/" + tooLong, "target"));
        }
    }

    @Test
    void listSkipsUnsafeDecryptedNames() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/ok.txt");

            byte[] iv = fs.readDirIV(fs.cipherRoot());
            Path root = fs.cipherRoot();
            String[] unsafe = {"..", ".", "a/b", "a\\b", "a\u0000b"};
            for (String name : unsafe) {
                String cName = fs.cipherNameFor(name, iv);
                Files.write(root.resolve(cName), new byte[0]);
            }

            List<String> names = fs.list("/").stream()
                    .map(DirEntry::plainName).collect(Collectors.toList());
            assertEquals(1, names.size());
            assertEquals("ok.txt", names.get(0));
        }
    }

    @Test
    void oversizedLongNameFileSkipped() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 220; i++) {
            longName.append('x');
        }
        String name = longName.toString();

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/" + name);
            String cipherName = fs.list("/").get(0).cipherName();
            assertNotNull(cipherName);
            Path nameFile = cipherDir.resolve(cipherName + ".name");
            assertTrue(Files.exists(nameFile), "long names use a .name support file");

            // Oversized .name content must be skipped like a corrupt name,
            // without breaking the whole listing or being buffered.
            Files.write(nameFile, new byte[8192]);
            assertTrue(fs.list("/").isEmpty());
        }
    }

    @Test
    void missingLongNameFileSkipped() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 220; i++) {
            longName.append('x');
        }
        String name = longName.toString();

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/" + name);
            String cipherName = fs.list("/").get(0).cipherName();
            assertNotNull(cipherName);
            Path nameFile = cipherDir.resolve(cipherName + ".name");
            assertTrue(Files.exists(nameFile), "long names use a .name support file");

            // A missing .name file must be skipped like a corrupt name.
            Files.delete(nameFile);
            assertTrue(fs.list("/").isEmpty());
        }
    }

    @Test
    void sparseWritesAndTruncate() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/hole.bin");

            // Write beyond EOF, creating a hole.
            byte[] tail = "tail".getBytes(StandardCharsets.UTF_8);
            fs.write("/hole.bin", 9000, tail);

            assertEquals(9000 + tail.length, fs.size("/hole.bin"));

            byte[] all = fs.readAll("/hole.bin");
            assertEquals(9000 + tail.length, all.length);
            for (int i = 0; i < 9000; i++) {
                assertEquals(0, all[i], "hole byte at " + i);
            }
            assertEquals("tail", new String(all, 9000, tail.length, StandardCharsets.UTF_8));

            // Truncate down and back up.
            fs.truncate("/hole.bin", 5000);
            assertEquals(5000, fs.size("/hole.bin"));
            fs.truncate("/hole.bin", 20000);
            assertEquals(20000, fs.size("/hole.bin"));
            byte[] grown = fs.readAll("/hole.bin");
            assertEquals(20000, grown.length);
        }
    }

}
