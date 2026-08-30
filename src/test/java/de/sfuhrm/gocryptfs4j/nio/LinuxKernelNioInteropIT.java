package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.fs.ContentCipherType;
import de.sfuhrm.gocryptfs4j.fs.GocryptFs;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
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
 * can be read back, in both directions, using the {@code java.nio.file}
 * {@link FileSystem} view ({@link GocryptFsProvider} / {@link GocryptFsFileSystem}):
 *
 * <ol>
 *   <li>gocryptfs (FUSE) writes the ciphertext, the NIO view reads it back.</li>
 *   <li>The NIO view writes the ciphertext, gocryptfs (FUSE) reads it back.</li>
 * </ol>
 *
 * <p>Every entry in the tree is verified via a manifest that records the file
 * type, size (in bytes), last-modified timestamp (in whole seconds) and a
 * SHA-256 digest of the content, walking the filesystem exclusively through the
 * {@code Files} API. Skipped automatically when {@code gocryptfs}, FUSE or
 * network access is unavailable. Run with {@code mvn verify}.</p>
 */
class LinuxKernelNioInteropIT {

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
            System.err.println("Skipping kernel NIO interop tests: " + e);
            sourceAvailable = false;
        }
    }

    static Stream<Arguments> variations() {
        return Stream.of(
                Arguments.of(false, ContentCipherType.AES_GCM),
                Arguments.of(false, ContentCipherType.XCHACHA20_POLY1305),
                Arguments.of(false, ContentCipherType.AES_SIV),
                Arguments.of(true, ContentCipherType.AES_GCM),
                Arguments.of(true, ContentCipherType.XCHACHA20_POLY1305),
                Arguments.of(true, ContentCipherType.AES_SIV)
        );
    }

    private static String cipherFlag(ContentCipherType cipherType) {
        switch (cipherType) {
            case XCHACHA20_POLY1305:
                return "-xchacha";
            case AES_SIV:
                return "-aessiv";
            default:
                return null;
        }
    }

    @ParameterizedTest(name = "plaintextNames={0}, cipher={1}")
    @MethodSource("variations")
    void gocryptfsWritesNioReads(boolean plaintextNames, ContentCipherType cipherType) throws Exception {
        assumeGocryptfs();
        assumeTrue(sourceAvailable, "kernel source could not be downloaded/extracted");

        Path cipherDir = Files.createDirectory(tmp.resolve("cipher-gocryptfs"));
        Path mount = Files.createDirectory(tmp.resolve("mount"));
        Path passfile = writePassfile();

        List<String> init = new ArrayList<>(Arrays.asList(
                "gocryptfs", "-init", "-passfile", passfile.toString()));
        if (plaintextNames) {
            init.add("-plaintextnames");
        }
        String flag = cipherFlag(cipherType);
        if (flag != null) {
            init.add(flag);
        }
        init.add(cipherDir.toString());
        run(init.toArray(new String[0]));

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

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, PASSWORD.toCharArray())) {
            assertManifestEquals(reference, manifest(nio.getPath("/linux")));
        }
    }

    @ParameterizedTest(name = "plaintextNames={0}, cipher={1}")
    @MethodSource("variations")
    void nioWritesGocryptfsReads(boolean plaintextNames, ContentCipherType cipherType) throws Exception {
        assumeGocryptfs();
        assumeTrue(sourceAvailable, "kernel source could not be downloaded/extracted");

        Path cipherDir = Files.createDirectory(tmp.resolve("cipher-java"));

        try (GocryptFs fs = GocryptFs.create(cipherDir, PASSWORD.toCharArray(), plaintextNames, cipherType)) {
            // Only the configuration is created here; the tree is written below
            // through the java.nio.file view.
        }

        GocryptFsProvider provider = new GocryptFsProvider();
        try (FileSystem nio = provider.newFileSystem(cipherDir, PASSWORD.toCharArray())) {
            Path linux = nio.getPath("/linux");
            Files.createDirectory(linux);
            copyInto(linuxSource, linux);
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
    // Tree copy / manifest (java.nio.file only)
    // ------------------------------------------------------------------

    /**
     * Recursively copies a plaintext directory tree into another (possibly
     * gocryptfs-backed) directory, using only the {@code Files} API.
     */
    private static void copyInto(Path src, Path dst) throws IOException {
        List<Path> children = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(src)) {
            ds.forEach(children::add);
        }
        children.sort(Path::compareTo);
        for (Path p : children) {
            Path target = dst.resolve(p.getFileName().toString());
            BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (attrs.isDirectory()) {
                Files.createDirectory(target);
                copyInto(p, target);
                Files.setLastModifiedTime(target, attrs.lastModifiedTime());
            } else if (attrs.isRegularFile()) {
                Files.write(target, Files.readAllBytes(p));
                Files.setLastModifiedTime(target, attrs.lastModifiedTime());
            } else if (attrs.isSymbolicLink()) {
                // The NIO view does not expose symlinks; the kernel 1.0 tree has none.
            }
        }
    }

    /**
     * Builds a {@code relative path -> digest} manifest of a directory tree.
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

    private static void assertManifestEquals(Map<String, String> expected,
                                             Map<String, String> actual) {
        assertEquals(expected.keySet(), actual.keySet(), "directory/file structure mismatch");
        for (String key : expected.keySet()) {
            assertEquals(expected.get(key), actual.get(key), "content mismatch for: " + key);
        }
        assertTrue(expected.size() > 500, "expected a large kernel source tree");
    }

    private static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static long mtime(FileTime time) {
        return time.to(TimeUnit.SECONDS);
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
