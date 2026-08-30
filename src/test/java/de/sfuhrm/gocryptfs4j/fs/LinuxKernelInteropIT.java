package de.sfuhrm.gocryptfs4j.fs;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test that downloads and extracts the Linux kernel 1.0 source
 * tree ({@code linux-1.0.tar.gz}) into a gocryptfs filesystem and verifies it
 * can be read back, in both directions:
 *
 * <ol>
 *   <li>gocryptfs (FUSE) writes the ciphertext, gocryptfs4j reads it back.</li>
 *   <li>gocryptfs4j writes the ciphertext, gocryptfs (FUSE) reads it back.</li>
 * </ol>
 *
 * <p>Every entry in the tree is verified via a manifest that records the file
 * type, size (in bytes), last-modified timestamp (in whole seconds) and a
 * SHA-256 digest of the content. Skipped automatically when {@code gocryptfs},
 * FUSE or network access is unavailable. Run with {@code mvn verify}.</p>
 */
class LinuxKernelInteropIT {

    private static final String KERNEL_URL =
            "https://www.kernel.org/pub/linux/kernel/v1.0/linux-1.0.tar.gz";
    private static final String PASSWORD = "testpass123";

    /** Shared download/extraction directory, reused across the two tests. */
    @TempDir
    static Path sourceRoot;

    /** Per-test working directory. */
    @TempDir
    Path tmp;

    private static Path linuxSource;
    private static Map<String, String> reference;
    private static boolean sourceAvailable;

    @BeforeAll
    static void downloadAndExtract() {
        try {
            Path tarball = sourceRoot.resolve("linux-1.0.tar.gz");
            download(KERNEL_URL, tarball);
            Path extract = Files.createDirectory(sourceRoot.resolve("extract"));
            run("tar", "-xzf", tarball.toString(), "-C", extract.toString());
            linuxSource = extract.resolve("linux");
            reference = manifest(linuxSource);
            sourceAvailable = true;
        } catch (Exception e) {
            System.err.println("Skipping kernel interop tests: " + e);
            sourceAvailable = false;
        }
    }

    static Stream<Boolean> plaintextNames() {
        return Stream.of(false, true);
    }

    @ParameterizedTest(name = "plaintextNames={0}")
    @MethodSource("plaintextNames")
    void gocryptfsWritesJavaReads(boolean plaintextNames) throws Exception {
        assumeGocryptfs();
        assumeTrue(sourceAvailable, "kernel source could not be downloaded/extracted");

        Path cipherDir = Files.createDirectory(tmp.resolve("cipher-gocryptfs"));
        Path mount = Files.createDirectory(tmp.resolve("mount"));
        Path passfile = writePassfile();

        if (plaintextNames) {
            run("gocryptfs", "-init", "-plaintextnames",
                    "-passfile", passfile.toString(), cipherDir.toString());
        } else {
            run("gocryptfs", "-init", "-passfile", passfile.toString(), cipherDir.toString());
        }

        Process mountProc = start("gocryptfs", "-passfile", passfile.toString(),
                cipherDir.toString(), mount.toString());
        try {
            waitForMount(mount);
            Path tarball = sourceRoot.resolve("linux-1.0.tar.gz");
            run("tar", "-xzf", tarball.toString(), "-C", mount.toString(), "--no-same-owner");
        } finally {
            unmount(mount);
            if (!mountProc.waitFor(30, TimeUnit.SECONDS)) {
                mountProc.destroyForcibly();
            }
        }

        try (GocryptFs fs = GocryptFs.open(cipherDir, PASSWORD)) {
            assertManifestEquals(reference, manifest(fs, "/linux"));
        }
    }

    @ParameterizedTest(name = "plaintextNames={0}")
    @MethodSource("plaintextNames")
    void javaWritesGocryptfsReads(boolean plaintextNames) throws Exception {
        assumeGocryptfs();
        assumeTrue(sourceAvailable, "kernel source could not be downloaded/extracted");

        Path cipherDir = Files.createDirectory(tmp.resolve("cipher-java"));

        try (GocryptFs fs = GocryptFs.create(cipherDir, PASSWORD.toCharArray(), plaintextNames)) {
            fs.mkdir("/linux");
            copyInto(fs, "/linux", linuxSource);
        }

        Path mount = Files.createDirectory(tmp.resolve("mount"));
        Path passfile = writePassfile();
        Process mountProc = start("gocryptfs", "-passfile", passfile.toString(),
                cipherDir.toString(), mount.toString());
        try {
            waitForMount(mount);
            assertManifestEquals(reference, manifest(mount.resolve("linux")));
        } finally {
            unmount(mount);
            if (!mountProc.waitFor(30, TimeUnit.SECONDS)) {
                mountProc.destroyForcibly();
            }
        }
    }

    // ------------------------------------------------------------------
    // Tree copy / manifest
    // ------------------------------------------------------------------

    /** Recursively copies a plaintext directory tree into a gocryptfs. */
    private static void copyInto(GocryptFs fs, String dir, Path src) throws IOException {
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(src)) {
            for (Path p : ds) {
                String name = p.getFileName().toString();
                String target = join(dir, name);
                BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
            if (attrs.isDirectory()) {
                fs.mkdir(target);
                copyInto(fs, target, p);
                fs.setTimes(target, attrs.lastModifiedTime(), null, null);
            } else if (attrs.isRegularFile()) {
                fs.createFile(target);
                fs.write(target, 0, Files.readAllBytes(p));
                fs.setTimes(target, attrs.lastModifiedTime(), null, null);
            } else if (attrs.isSymbolicLink()) {
                fs.createSymlink(target, Files.readSymbolicLink(p).toString());
            }
            }
        }
    }

    /**
     * Builds a {@code relative path -> digest} manifest of a plaintext tree.
     * Directories are recorded with a trailing slash and value {@code dir};
     * regular files with {@code sha256:<hex>}; symlinks with {@code link:<target>}.
     */
    private static Map<String, String> manifest(Path root) throws IOException {
        Map<String, String> out = new TreeMap<>();
        collectManifest(root, root, out);
        return out;
    }

    private static void collectManifest(Path root, Path dir, Map<String, String> out)
            throws IOException {
        List<Path> children = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
            ds.forEach(children::add);
        }
        children.sort(Path::compareTo);
        for (Path p : children) {
            String rel = root.relativize(p).toString().replace('\\', '/');
            BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (attrs.isDirectory()) {
                out.put(rel + "/", "dir mtime=" + mtime(attrs.lastModifiedTime()));
                collectManifest(root, p, out);
            } else if (attrs.isRegularFile()) {
                out.put(rel, "size=" + attrs.size() + " mtime=" + mtime(attrs.lastModifiedTime())
                        + " sha256=" + sha256(Files.readAllBytes(p)));
            } else if (attrs.isSymbolicLink()) {
                out.put(rel, "link " + Files.readSymbolicLink(p));
            } else {
                out.put(rel, "other");
            }
        }
    }

    /** Builds the same manifest from the plaintext view of a {@link GocryptFs}. */
    private static Map<String, String> manifest(GocryptFs fs, String dir) throws IOException {
        Map<String, String> out = new TreeMap<>();
        collectManifest(fs, dir, "", out);
        return out;
    }

    private static void collectManifest(GocryptFs fs, String dir, String prefix,
                                        Map<String, String> out) throws IOException {
        for (DirEntry e : fs.list(dir)) {
            String rel = prefix + e.plainName();
            if (e.isDirectory()) {
                out.put(rel + "/", "dir mtime=" + mtime(e.lastModifiedTime()));
                collectManifest(fs, join(dir, e.plainName()), rel + "/", out);
            } else if (e.isRegularFile()) {
                out.put(rel, "size=" + e.size() + " mtime=" + mtime(e.lastModifiedTime())
                        + " sha256=" + sha256(fs.readAll(join(dir, e.plainName()))));
            } else if (e.isSymbolicLink()) {
                out.put(rel, "link " + fs.readSymlinkTarget(join(dir, e.plainName())));
            } else {
                out.put(rel, "other");
            }
        }
    }

    private static void assertManifestEquals(Map<String, String> expected,
                                             Map<String, String> actual) {
        assertEquals(expected.keySet(), actual.keySet(), "directory/file structure mismatch");
        for (String key : expected.keySet()) {
            assertEquals(expected.get(key), actual.get(key), "content mismatch for: " + key);
        }
        assertTrue(expected.size() > 500, "expected a large kernel source tree");
    }

    private static String join(String dir, String name) {
        return dir.equals("/") ? "/" + name : dir + "/" + name;
    }

    private static long mtime(FileTime time) {
        return time.to(TimeUnit.SECONDS);
    }

    private static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------
    // Download
    // ------------------------------------------------------------------

    private static void download(String url, Path dest) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(30))
                .build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .build();
        HttpResponse<InputStream> response =
                client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() != 200) {
            throw new IOException("download failed: HTTP " + response.statusCode() + " " + url);
        }
        try (InputStream in = response.body()) {
            Files.copy(in, dest, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    // ------------------------------------------------------------------
    // gocryptfs / FUSE helpers
    // ------------------------------------------------------------------

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
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(120, TimeUnit.SECONDS) || p.exitValue() != 0) {
            throw new IOException("command failed: " + Arrays.toString(cmd) + "\n" + out);
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
