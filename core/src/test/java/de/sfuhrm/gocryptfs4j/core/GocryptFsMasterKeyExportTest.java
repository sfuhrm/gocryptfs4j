package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.config.ConfigFile;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GocryptFsMasterKeyExportTest {

    @TempDir
    Path tmp;

    @Test
    void exportedKeyMatchesConfigAndCanReopenTheFilesystem() throws IOException {
        PathCipherStore store = new PathCipherStore(tmp);
        byte[] data = "secret".getBytes(StandardCharsets.UTF_8);
        byte[] exported;
        try (GocryptFs fs = GocryptFs.create(store, "pw".toCharArray())) {
            fs.createFile("/f.txt");
            fs.write("/f.txt", 0, data);
            exported = fs.exportMasterKey();
            assertArrayEquals(ConfigFile.load(store).decryptMasterKey("pw".toCharArray()),
                    exported);
        }

        try (GocryptFs fs = GocryptFs.open(store, exported)) {
            assertArrayEquals(data, fs.readAll("/f.txt"));
        } finally {
            Arrays.fill(exported, (byte) 0);
        }
    }

    @Test
    void exportReturnsACallerOwnedCopy() throws IOException {
        PathCipherStore store = new PathCipherStore(tmp);
        try (GocryptFs fs = GocryptFs.create(store, "pw".toCharArray())) {
            byte[] first = fs.exportMasterKey();
            byte[] expected = first.clone();
            Arrays.fill(first, (byte) 0);
            assertArrayEquals(expected, fs.exportMasterKey());
        }
    }

    @Test
    void exportedKeyRemainsUsableAfterCloseAndExportFailsOnClosedFilesystem() throws IOException {
        PathCipherStore store = new PathCipherStore(tmp);
        GocryptFs fs = GocryptFs.create(store, "pw".toCharArray());
        byte[] exported = fs.exportMasterKey();
        fs.close();

        assertThrows(IllegalStateException.class, fs::exportMasterKey);
        try (GocryptFs reopened = GocryptFs.open(store, exported)) {
            assertTrue(reopened.list("/").isEmpty());
        } finally {
            Arrays.fill(exported, (byte) 0);
        }
    }

    @Test
    void formatsLikeGocryptfsMasterKeyReminder() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) i;
        }
        assertEquals("00010203-04050607-08090a0b-0c0d0e0f"
                        + "-10111213-14151617-18191a1b-1c1d1e1f",
                GocryptFs.formatMasterKey(key));
    }

    @Test
    void changePasswordDoesNotKeepABackupByDefault() throws IOException {
        PathCipherStore store = new PathCipherStore(tmp);
        try (GocryptFs fs = GocryptFs.create(store, "old".toCharArray())) {
            fs.changePassword("new".toCharArray());
        }

        assertFalse(Files.exists(tmp.resolve("gocryptfs.conf.bak")),
                "a password change must not keep the old password usable by default");
        assertThrows(IOException.class,
                () -> GocryptFs.open(store, "old".toCharArray()));
        try (GocryptFs fs = GocryptFs.open(store, "new".toCharArray())) {
            assertTrue(fs.list("/").isEmpty());
        }
    }

    @Test
    void changePasswordCanKeepABackupOfTheOldConfig() throws IOException {
        PathCipherStore store = new PathCipherStore(tmp);
        try (GocryptFs fs = GocryptFs.create(store, "old".toCharArray())) {
            fs.createFile("/f.txt");
            fs.changePassword("new".toCharArray(), true);
        }

        Path backup = tmp.resolve("gocryptfs.conf.bak");
        assertTrue(Files.exists(backup));
        assertEquals(PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(backup),
                "the backup contains the old encrypted master key and must be 0400");
        byte[] oldKey = ConfigFile.fromBytes(Files.readAllBytes(backup))
                .decryptMasterKey("old".toCharArray());
        assertFalse(Arrays.equals(new byte[oldKey.length], oldKey));
        try (GocryptFs fs = GocryptFs.open(store, "new".toCharArray())) {
            assertEquals(DirEntry.Kind.FILE, fs.stat("/f.txt").kind());
        }
    }
}
