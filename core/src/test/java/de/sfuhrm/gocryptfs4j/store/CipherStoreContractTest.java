package de.sfuhrm.gocryptfs4j.store;

import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;
import de.sfuhrm.gocryptfs4j.store.memory.MapCipherStore;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A contract test suite for the {@link CipherStore} SPI. It runs the same
 * assertions against every store implementation so that a store used as a
 * test double for a remote backend does not silently pass with more forgiving
 * semantics than a real filesystem.
 */
class CipherStoreContractTest {

    @TempDir
    Path tempDir;

    static Stream<Backend> backends() {
        return Stream.of(Backend.values());
    }

    /**
     * A store factory, one per store implementation under test.
     */
    enum Backend {
        MEMORY {
            @Override
            CipherStore create(Path temp) {
                return new MapCipherStore();
            }
        },
        LOCAL {
            @Override
            CipherStore create(Path temp) throws IOException {
                return new PathCipherStore(Files.createDirectory(temp.resolve("cipher")));
            }
        };

        abstract CipherStore create(Path temp) throws IOException;
    }

    /**
     * Builds a ciphertext name by joining {@code parts} onto the store root.
     */
    private static String path(CipherStore store, String... parts) {
        String root = store.root();
        String relative = String.join("/", parts);
        return root.isEmpty() ? relative : root + "/" + relative;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void createFileRequiresExistingParent(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        assertThrows(NoSuchFileException.class,
                () -> store.createFile(path(store, "missing", "f")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void mkdirRequiresExistingParent(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        assertThrows(NoSuchFileException.class,
                () -> store.mkdir(path(store, "missing", "d")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void writeSmallRequiresExistingParent(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        byte[] data = "data".getBytes(StandardCharsets.UTF_8);
        assertThrows(NoSuchFileException.class,
                () -> store.writeSmall(path(store, "missing", "f"), data, false));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void createSymlinkRequiresExistingParent(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        assertThrows(NoSuchFileException.class,
                () -> store.createSymlink(path(store, "missing", "l"), "target"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void createFileRejectsExistingEntry(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        store.createFile(path(store, "f"));
        assertThrows(FileAlreadyExistsException.class, () -> store.createFile(path(store, "f")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void mkdirRejectsExistingEntry(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        store.mkdir(path(store, "d"));
        assertThrows(FileAlreadyExistsException.class, () -> store.mkdir(path(store, "d")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void writeSmallWithoutOverwriteRejectsExistingFile(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        store.writeSmall(path(store, "f"), "old".getBytes(StandardCharsets.UTF_8), false);
        assertThrows(FileAlreadyExistsException.class,
                () -> store.writeSmall(path(store, "f"), "new".getBytes(StandardCharsets.UTF_8),
                        false));
        assertArrayEquals("old".getBytes(StandardCharsets.UTF_8),
                store.readSmall(path(store, "f"), 100));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void writeSmallWithOverwriteReplacesContent(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        store.writeSmall(path(store, "f"), "old".getBytes(StandardCharsets.UTF_8), false);
        store.writeSmall(path(store, "f"), "new".getBytes(StandardCharsets.UTF_8), true);
        assertArrayEquals("new".getBytes(StandardCharsets.UTF_8),
                store.readSmall(path(store, "f"), 100));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void createdEntriesAreListed(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        store.mkdir(path(store, "d"));
        store.createFile(path(store, "d", "f"));
        store.createSymlink(path(store, "d", "l"), "f");

        Set<String> names = store.list(path(store, "d")).stream()
                .map(CipherNode::name)
                .collect(Collectors.toSet());
        assertEquals(new HashSet<>(Arrays.asList("f", "l")), names);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void symlinkSizeIsMeasuredInBytes(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        store.mkdir(path(store, "d"));
        String target = "é";
        store.createSymlink(path(store, "d", "l"), target);

        assertEquals(target.getBytes(StandardCharsets.UTF_8).length,
                store.stat(path(store, "d", "l")).size());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void renameDirectoryMovesEntireSubtree(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        store.mkdir(path(store, "d1"));
        store.mkdir(path(store, "d1", "sub"));
        store.writeSmall(path(store, "d1", "sub", "f"),
                "deep".getBytes(StandardCharsets.UTF_8), false);

        store.rename(path(store, "d1"), path(store, "d2"), false);

        assertArrayEquals("deep".getBytes(StandardCharsets.UTF_8),
                store.readSmall(path(store, "d2", "sub", "f"), 100));
        assertThrows(NoSuchFileException.class, () -> store.stat(path(store, "d1", "sub", "f")));
        assertThrows(NoSuchFileException.class, () -> store.stat(path(store, "d1")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void deleteRejectsNonEmptyDirectory(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        store.mkdir(path(store, "d"));
        store.createFile(path(store, "d", "f"));

        assertThrows(DirectoryNotEmptyException.class, () -> store.delete(path(store, "d")));

        store.delete(path(store, "d", "f"));
        store.delete(path(store, "d"));
        assertThrows(NoSuchFileException.class, () -> store.stat(path(store, "d")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void statAndListOfMissingEntryThrow(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        assertThrows(NoSuchFileException.class, () -> store.stat(path(store, "missing")));
        assertThrows(NoSuchFileException.class, () -> store.list(path(store, "missing")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backends")
    void readSymlinkRoundTripsTarget(Backend backend) throws IOException {
        CipherStore store = backend.create(tempDir);
        store.createSymlink(path(store, "l"), "some/target");
        assertEquals("some/target", store.readSymlink(path(store, "l")));
        assertTrue(store.list(store.root()).stream()
                .anyMatch(n -> n.isSymbolicLink() && n.name().equals("l")));
    }
}
