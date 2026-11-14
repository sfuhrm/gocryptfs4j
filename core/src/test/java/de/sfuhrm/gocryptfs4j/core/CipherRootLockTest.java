package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the writer lock and the explicit read-only mode.
 */
class CipherRootLockTest {

    @TempDir
    Path tmp;

    @Test
    void writableOpenIsExclusiveAndReleasedOnClose() throws IOException {
        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        byte[] data = "secret".getBytes(StandardCharsets.UTF_8);

        GocryptFs first = GocryptFs.create(new PathCipherStore(cipherDir), "pw".toCharArray());
        try {
            first.createFile("/f");
            first.write("/f", 0, data);

            assertThrows(IOException.class,
                    () -> GocryptFs.open(new PathCipherStore(cipherDir), "pw".toCharArray()),
                    "a second writable open must fail while the first is open");

            try (GocryptFs readOnly = GocryptFs.openReadOnly(
                    new PathCipherStore(cipherDir), "pw".toCharArray())) {
                assertArrayEquals(data, readOnly.readAll("/f"));
                assertThrows(IOException.class,
                        () -> readOnly.write("/f", 0, new byte[]{1}),
                        "a read-only filesystem must reject writes");
                assertThrows(IOException.class,
                        () -> readOnly.createFile("/g"),
                        "a read-only filesystem must reject creation");
            }
        } finally {
            first.close();
        }

        try (GocryptFs reopened = GocryptFs.open(
                new PathCipherStore(cipherDir), "pw".toCharArray())) {
            assertArrayEquals(data, reopened.readAll("/f"));
        }
    }

    @Test
    void failedOpenReleasesTheLock() throws IOException {
        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        try (GocryptFs ignored = GocryptFs.create(
                new PathCipherStore(cipherDir), "pw".toCharArray())) {
            // just create the filesystem
        }

        assertThrows(IOException.class,
                () -> GocryptFs.open(new PathCipherStore(cipherDir), "wrong".toCharArray()));

        try (GocryptFs fs = GocryptFs.open(
                new PathCipherStore(cipherDir), "pw".toCharArray())) {
            assertTrue(fs.list("/").isEmpty());
        }
    }

    @Test
    void lockIsKeptAcrossChangePassword() throws IOException {
        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        try (GocryptFs fs = GocryptFs.create(
                new PathCipherStore(cipherDir), "old".toCharArray())) {
            fs.changePassword("new".toCharArray());
            assertThrows(IOException.class,
                    () -> GocryptFs.open(new PathCipherStore(cipherDir), "new".toCharArray()),
                    "changing the password must not release the writer lock");
        }

        try (GocryptFs fs = GocryptFs.open(
                new PathCipherStore(cipherDir), "new".toCharArray())) {
            assertTrue(fs.list("/").isEmpty());
        }
    }

    @Test
    void readOnlyListingDoesNotCreateDirIV() throws IOException {
        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        Path dirCipher;
        try (GocryptFs fs = GocryptFs.create(
                new PathCipherStore(cipherDir), "pw".toCharArray())) {
            fs.mkdir("/dir");
            dirCipher = java.nio.file.Paths.get(fs.resolve("/dir").cipherPath());
        }

        Path dirIV = dirCipher.resolve("gocryptfs.diriv");
        Files.delete(dirIV);
        Set<String> before = entries(dirCipher);

        try (GocryptFs fs = GocryptFs.openReadOnly(
                new PathCipherStore(cipherDir), "pw".toCharArray())) {
            assertTrue(fs.list("/dir").isEmpty());
        }

        assertFalse(Files.exists(dirIV),
                "a read-only filesystem must not create gocryptfs.diriv");
        assertEquals(before, entries(dirCipher),
                "a read-only filesystem must not change the cipher directory");
    }

    @Test
    void readOnlyCanCoexistWithWritableAndTheStoreCanBeReused() throws IOException {
        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        CipherStore store = new PathCipherStore(cipherDir);
        try (GocryptFs writable = GocryptFs.create(store, "pw".toCharArray())) {
            writable.createFile("/f");
            assertThrows(IOException.class, () -> GocryptFs.open(store, "pw".toCharArray()));
            try (GocryptFs readOnly = GocryptFs.openReadOnly(store, "pw".toCharArray())) {
                assertTrue(readOnly.list("/").stream()
                        .anyMatch(e -> e.plainName().equals("f")));
            }
        }
    }

    private static Set<String> entries(Path dir) throws IOException {
        return Files.list(dir)
                .map(p -> p.getFileName().toString())
                .collect(Collectors.toCollection(HashSet::new));
    }
}
