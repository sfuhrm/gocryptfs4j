package de.sfuhrm.gocryptfs4j.store.memory;

import de.sfuhrm.gocryptfs4j.core.DirEntry;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves that {@link GocryptFs} works over a non-local
 * {@link de.sfuhrm.gocryptfs4j.store.CipherStore}, using {@link MapCipherStore}
 * as the reference in-memory backend.
 */
class MapCipherStoreTest {

    @Test
    void roundTripsOverInMemoryStore() throws IOException {
        MapCipherStore store = new MapCipherStore();
        byte[] content = "hello in-memory store".getBytes(StandardCharsets.UTF_8);

        try (GocryptFs fs = GocryptFs.create(store, "pw".toCharArray())) {
            fs.mkdir("/docs");
            fs.createFile("/docs/note.txt");
            fs.write("/docs/note.txt", 0, content);
            fs.createSymlink("/docs/link", "note.txt");

            assertArrayEquals(content, fs.readAll("/docs/note.txt"));
            assertEquals("note.txt", fs.readSymlinkTarget("/docs/link"));
            List<String> names = fs.list("/docs").stream()
                    .map(DirEntry::plainName).collect(Collectors.toList());
            assertTrue(names.contains("note.txt"));
            assertTrue(names.contains("link"));
        }

        // Re-open the same store and verify the data persisted in memory.
        try (GocryptFs fs = GocryptFs.open(store, "pw".toCharArray())) {
            assertArrayEquals(content, fs.readAll("/docs/note.txt"));
        }
    }

    @Test
    void renameAndDeleteOverInMemoryStore() throws IOException {
        MapCipherStore store = new MapCipherStore();

        try (GocryptFs fs = GocryptFs.create(store, "pw".toCharArray())) {
            fs.createFile("/a.txt");
            fs.write("/a.txt", 0, "data".getBytes(StandardCharsets.UTF_8));
            fs.mkdir("/d1");
            fs.mkdir("/d1/sub");
            fs.createFile("/d1/sub/f.txt");
            fs.write("/d1/sub/f.txt", 0, "deep".getBytes(StandardCharsets.UTF_8));

            fs.rename("/a.txt", "/b.txt", false);
            assertArrayEquals("data".getBytes(StandardCharsets.UTF_8), fs.readAll("/b.txt"));

            fs.rename("/d1", "/d2", false);
            assertArrayEquals("deep".getBytes(StandardCharsets.UTF_8), fs.readAll("/d2/sub/f.txt"));

            fs.delete("/b.txt");
            assertTrue(fs.list("/").stream().noneMatch(e -> e.plainName().equals("b.txt")));
        }
    }

    @Test
    void uriDispatchCreatesAndUsesMemoryStore() throws IOException {
        byte[] content = "via uri".getBytes(StandardCharsets.UTF_8);

        try (GocryptFs fs = GocryptFs.create(URI.create("memory:///"), Collections.emptyMap(),
                "pw".toCharArray())) {
            fs.createFile("/f.txt");
            fs.write("/f.txt", 0, content);
            assertArrayEquals(content, fs.readAll("/f.txt"));
            assertEquals(1, fs.list("/").size());
        }
    }
}
