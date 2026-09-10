package de.sfuhrm.gocryptfs4j.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Golden test that opens the {@code v1.3} example filesystem shipped with the
 * reference gocryptfs implementation and verifies its plaintext contents.
 *
 * <p>The ciphertext tree (password {@code "test"}) is committed under
 * {@code core/src/test/resources/example-fs-v1.3/} and exercises the full
 * forward-mode on-disk format: HKDF sub-keys, directory IVs, EME name
 * encryption, GCM content encryption, long-name handling and symlinks.</p>
 */
class GocryptfsExampleFsGoldenTest {

    private static final String LONG_NAME = "longname_255_" + "x".repeat(242);

    @TempDir
    Path tmp;

    @Test
    void readsGocryptFsV13ExampleFilesystem() throws Exception {
        Path cipherDir = copyResource("/example-fs-v1.3", tmp.resolve("cipher"));
        restoreSymlinks(cipherDir);

        try (GocryptFs fs = GocryptFs.open(cipherDir, "test".toCharArray())) {
            List<DirEntry> entries = fs.list("/");
            Set<String> names = entries.stream()
                    .map(DirEntry::plainName)
                    .collect(Collectors.toSet());
            assertEquals(Set.of("status.txt", "rel", "abs", LONG_NAME), names);

            assertEquals("It works!\n",
                    new String(fs.readAll("/status.txt"), StandardCharsets.UTF_8));
            assertEquals("status.txt", fs.readSymlinkTarget("/rel"));
            assertEquals("/a/b/c/d", fs.readSymlinkTarget("/abs"));
            assertEquals("It works!\n",
                    new String(fs.readAll("/" + LONG_NAME), StandardCharsets.UTF_8));
        }
    }

    /**
     * Git and raw HTTP downloads cannot represent symlinks, so the example
     * filesystem's symlink targets are committed as regular files and re-linked
     * here from the {@code example-fs-v1.3-symlinks.txt} manifest.
     */
    private static void restoreSymlinks(Path cipherDir) throws Exception {
        URL manifest = GocryptfsExampleFsGoldenTest.class
                .getResource("/example-fs-v1.3-symlinks.txt");
        for (String line : Files.readAllLines(Path.of(manifest.toURI()))) {
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int eq = line.indexOf('=');
            Path link = cipherDir.resolve(line.substring(0, eq));
            String target = line.substring(eq + 1);
            Files.delete(link);
            Files.createSymbolicLink(link, Path.of(target));
        }
    }

    private static Path copyResource(String resource, Path dest) throws Exception {
        Path src = Path.of(Objects.requireNonNull(
                GocryptfsExampleFsGoldenTest.class.getResource(resource)).toURI());
        try (Stream<Path> walk = Files.walk(src)) {
            for (Path p : walk.collect(Collectors.toList())) {
                Path target = dest.resolve(src.relativize(p).toString());
                if (Files.isDirectory(p)) {
                    Files.createDirectories(target);
                } else {
                    Files.copy(p, target, java.nio.file.LinkOption.NOFOLLOW_LINKS);
                }
            }
        }
        return dest;
    }
}
