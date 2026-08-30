package de.sfuhrm.gocryptfs4j.fs;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test that runs this Java implementation against the real
 * {@code gocryptfs} binary, in both directions:
 *
 * <ol>
 *   <li>gocryptfs creates the ciphertext, Java reads it back.</li>
 *   <li>Java creates the ciphertext, gocryptfs mounts and reads it back.</li>
 * </ol>
 *
 * <p>Skipped automatically when {@code gocryptfs} or FUSE is not available.
 * Run with {@code mvn verify} (the Failsafe plugin picks up {@code *IT.java}).</p>
 */
class GocryptfsInteropIT {

    private static final String PASSWORD = "testpass123";

    @TempDir
    Path tmp;

    static Stream<Arguments> variations() {
        return Stream.of(
                Arguments.of(false, false),
                Arguments.of(false, true),
                Arguments.of(true, false),
                Arguments.of(true, true)
        );
    }

    @ParameterizedTest(name = "plaintextNames={0}, xchacha={1}")
    @MethodSource("variations")
    void gocryptfsWritesJavaReads(boolean plaintextNames, boolean xchacha) throws Exception {
        assumeGocryptfs();

        Path cipherDir = Files.createDirectory(tmp.resolve("cipher-gocryptfs"));
        Path mount = Files.createDirectory(tmp.resolve("mount"));
        Path passfile = writePassfile();

        List<String> init = new ArrayList<>(Arrays.asList(
                "gocryptfs", "-init", "-passfile", passfile.toString()));
        if (plaintextNames) {
            init.add("-plaintextnames");
        }
        if (xchacha) {
            init.add("-xchacha");
        }
        init.add(cipherDir.toString());
        run(init.toArray(new String[0]));

        Process mountProc = start("gocryptfs", "-passfile", passfile.toString(),
                cipherDir.toString(), mount.toString());
        try {
            waitForMount(mount);

            Files.createDirectories(mount.resolve("sub"));
            Files.writeString(mount.resolve("hello.txt"), "hello world", StandardCharsets.UTF_8);
            Files.write(mount.resolve("sub/big.bin"), bigData());
            Files.writeString(mount.resolve(longName()), longNameContent(), StandardCharsets.UTF_8);
        } finally {
            unmount(mount);
            if (!mountProc.waitFor(30, TimeUnit.SECONDS)) {
                mountProc.destroyForcibly();
            }
        }

        try (GocryptFs fs = GocryptFs.open(cipherDir, PASSWORD)) {
            Set<String> root = fs.list("/").stream()
                    .map(DirEntry::plainName).collect(Collectors.toSet());
            assertEquals(Set.of("sub", "hello.txt", longName()), root);

            assertEquals("hello world",
                    new String(fs.readAll("/hello.txt"), StandardCharsets.UTF_8));
            assertArrayEquals(bigData(), fs.readAll("/sub/big.bin"));
            assertEquals(longNameContent(),
                    new String(fs.readAll("/" + longName()), StandardCharsets.UTF_8));
        }
    }

    @ParameterizedTest(name = "plaintextNames={0}, xchacha={1}")
    @MethodSource("variations")
    void javaWritesGocryptfsReads(boolean plaintextNames, boolean xchacha) throws Exception {
        assumeGocryptfs();

        Path cipherDir = Files.createDirectory(tmp.resolve("cipher-java"));
        Path passfile = writePassfile();

        try (GocryptFs fs = GocryptFs.create(cipherDir, PASSWORD.toCharArray(), plaintextNames, xchacha)) {
            fs.mkdir("/sub");
            fs.createFile("/hello.txt");
            fs.write("/hello.txt", 0, "hello world".getBytes(StandardCharsets.UTF_8));
            fs.createFile("/sub/big.bin");
            fs.write("/sub/big.bin", 0, bigData());
            fs.createFile("/" + longName());
            fs.write("/" + longName(), 0, longNameContent().getBytes(StandardCharsets.UTF_8));
        }

        Path mount = Files.createDirectory(tmp.resolve("mount"));
        Process mountProc = start("gocryptfs", "-passfile", passfile.toString(),
                cipherDir.toString(), mount.toString());
        try {
            waitForMount(mount);

            assertEquals("hello world", Files.readString(mount.resolve("hello.txt")));
            assertArrayEquals(bigData(), Files.readAllBytes(mount.resolve("sub/big.bin")));
            assertEquals(longNameContent(), Files.readString(mount.resolve(longName())));

            try (var stream = Files.list(mount)) {
                Set<String> names = stream.map(p -> p.getFileName().toString())
                        .collect(Collectors.toSet());
                assertEquals(Set.of("sub", "hello.txt", longName()), names);
            }
        } finally {
            unmount(mount);
            if (!mountProc.waitFor(30, TimeUnit.SECONDS)) {
                mountProc.destroyForcibly();
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static byte[] bigData() {
        byte[] data = new byte[256 * 1024];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 31 + 7);
        }
        return data;
    }

    /** A name long enough to trigger gocryptfs long-name handling (&gt;175 chars). */
    private static String longName() {
        StringBuilder sb = new StringBuilder("long-");
        while (sb.length() < 220) {
            sb.append("segment").append(sb.length()).append('-');
        }
        return sb.substring(0, 220);
    }

    private static String longNameContent() {
        return "content of a file with a very long name";
    }

    private Path writePassfile() throws IOException {
        Path p = tmp.resolve("passfile-" + System.nanoTime());
        Files.writeString(p, PASSWORD, StandardCharsets.UTF_8);
        return p;
    }

    private static void assumeGocryptfs() throws InterruptedException, IOException {
        boolean haveBinary;
        try {
            Process p = new ProcessBuilder("gocryptfs", "-version")
                    .redirectErrorStream(true).start();
            haveBinary = p.waitFor() == 0;
        } catch (IOException e) {
            haveBinary = false;
        }
        boolean haveFuse = Files.exists(Path.of("/dev/fuse"));
        assumeTrue(haveBinary, "gocryptfs binary not found on PATH");
        assumeTrue(haveFuse, "FUSE (/dev/fuse) not available");
    }

    private static Process start(String... cmd) throws IOException {
        Path log = Files.createTempFile("gocryptfs-", ".log");
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.redirectOutput(log.toFile());
        return pb.start();
    }

    private static void run(String... cmd) throws IOException, InterruptedException {
        Process p = start(cmd);
        if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) {
            throw new IOException("command failed: " + Arrays.toString(cmd));
        }
    }

    private static void waitForMount(Path mount) throws IOException, InterruptedException {
        for (int i = 0; i < 150; i++) {
            if (isMounted(mount)) {
                return;
            }
            Thread.sleep(100);
        }
        throw new IOException("mount did not become ready: " + mount);
    }

    private static boolean isMounted(Path mount) throws IOException {
        String real = mount.toRealPath().toString();
        for (String line : Files.readAllLines(Path.of("/proc/mounts"))) {
            if (line.contains(real)) {
                return true;
            }
        }
        return false;
    }

    private static void unmount(Path mount) {
        try {
            run("fusermount", "-u", mount.toString());
        } catch (Exception e) {
            try {
                run("umount", mount.toString());
            } catch (Exception ignored) {
                // Best effort; the test JVM is about to exit anyway.
            }
        }
    }
}
