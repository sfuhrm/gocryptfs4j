package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the explicit read-only mode of the NIO provider.
 */
class GocryptFsReadOnlyTest {

    @TempDir
    Path tmp;

    @Test
    void readOnlyFileSystemCoexistsWithWritableAndRejectsWrites() throws IOException {
        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        byte[] data = "content".getBytes(StandardCharsets.UTF_8);
        try (GocryptFs fs = GocryptFs.create(
                new PathCipherStore(cipherDir), "pw".toCharArray())) {
            fs.createFile("/f");
            fs.write("/f", 0, data);
        }

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem writable = provider.newFileSystem(cipherDir, "pw".toCharArray());
             FileSystem readOnly = provider.newFileSystem(
                     cipherDir, "pw".toCharArray(), false, true)) {
            assertFalse(writable.isReadOnly());
            assertTrue(readOnly.isReadOnly());
            assertArrayEquals(data,
                    Files.readAllBytes(readOnly.getPath("/f")));
            assertThrows(IOException.class,
                    () -> Files.write(readOnly.getPath("/g"), new byte[]{1}));
        }
    }
}
