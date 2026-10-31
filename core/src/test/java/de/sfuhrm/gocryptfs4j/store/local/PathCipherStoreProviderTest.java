package de.sfuhrm.gocryptfs4j.store.local;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Verifies that the local filesystem is reachable through the URI dispatch via
 * the {@code file} scheme.
 */
class PathCipherStoreProviderTest {

    @TempDir
    Path tmp;

    @Test
    void fileUriDispatchRoundTrip() throws Exception {
        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        URI uri = cipherDir.toUri();

        byte[] content = "via file uri".getBytes(StandardCharsets.UTF_8);

        try (GocryptFs fs = GocryptFs.create(uri, Collections.emptyMap(), "pw".toCharArray())) {
            fs.createFile("/f.txt");
            fs.write("/f.txt", 0, content);
            assertArrayEquals(content, fs.readAll("/f.txt"));
            assertEquals(1, fs.list("/").size());
        }

        try (GocryptFs fs = GocryptFs.open(uri, Collections.emptyMap(), "pw".toCharArray())) {
            assertArrayEquals(content, fs.readAll("/f.txt"));
        }
    }
}
