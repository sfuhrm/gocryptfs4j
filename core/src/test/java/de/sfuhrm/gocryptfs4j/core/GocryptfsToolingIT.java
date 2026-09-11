package de.sfuhrm.gocryptfs4j.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Uses the reference {@code gocryptfs} binary as an oracle against cipher
 * directories written by gocryptfs4j.
 *
 * <p>{@code -info} and {@code -passwd} require only the {@code gocryptfs}
 * binary; {@code -fsck} additionally requires FUSE. The tests are skipped when
 * the required tools are unavailable.</p>
 */
class GocryptfsToolingIT {

    private static final String PASSWORD = "testpass123";

    @TempDir
    Path tmp;

    @Test
    void infoReadsJavaWrittenConfig() throws Exception {
        assumeGocryptfsBinary();

        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        try (GocryptFs fs = GocryptFs.create(cipherDir, PASSWORD.toCharArray())) {
            fs.createFile("/hello.txt");
            fs.write("/hello.txt", 0, "hello".getBytes(StandardCharsets.UTF_8));
        }

        ProcessResult r = run("gocryptfs", "-info", cipherDir.toString());
        assertEquals(0, r.exitCode, "gocryptfs -info failed:\n" + r.output);
        assertTrue(r.output.contains("FeatureFlags"), "missing FeatureFlags:\n" + r.output);
        assertTrue(r.output.contains("HKDF"), "missing HKDF flag:\n" + r.output);
        assertTrue(r.output.contains("gocryptfs4j"), "missing creator string:\n" + r.output);
    }

    @Test
    void fsckAcceptsJavaWrittenFilesystem() throws Exception {
        assumeFuse();
        assumeTrue(GocryptfsCli.supports("-fsck"), "gocryptfs does not support -fsck");

        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        try (GocryptFs fs = GocryptFs.create(cipherDir, PASSWORD.toCharArray())) {
            fs.mkdir("/sub");
            fs.createFile("/sub/data.bin");
            fs.write("/sub/data.bin", 0, bigData());
        }

        Path passfile = writePassfile();
        ProcessResult r = run("gocryptfs", "-fsck", "-passfile", passfile.toString(),
                cipherDir.toString());
        assertEquals(0, r.exitCode, "gocryptfs -fsck reported corruption:\n" + r.output);
    }

    @Test
    void passwdRoundTrip() throws Exception {
        assumeGocryptfsBinary();

        Path cipherDir = Files.createDirectory(tmp.resolve("cipher"));
        try (GocryptFs fs = GocryptFs.create(cipherDir, PASSWORD.toCharArray())) {
            fs.createFile("/hello.txt");
            fs.write("/hello.txt", 0, "hello world".getBytes(StandardCharsets.UTF_8));
        }

        Path oldPassfile = writePassfile();
        String newPassword = "brand-new-password";
        // gocryptfs reads the old and new password from stdin (one per line)
        // when no -passfile/-extpass is given. This works on every gocryptfs
        // version, unlike relying on -passfile for the old password (which some
        // versions also reuse as the new password).
        ProcessResult r = runWithInput(
                (PASSWORD + "\n" + newPassword + "\n").getBytes(StandardCharsets.UTF_8),
                "gocryptfs", "-passwd", cipherDir.toString());
        assertEquals(0, r.exitCode, "gocryptfs -passwd failed:\n" + r.output);

        // New password opens and reads; old password is rejected.
        try (GocryptFs fs = GocryptFs.open(cipherDir, newPassword.toCharArray())) {
            assertEquals("hello world",
                    new String(fs.readAll("/hello.txt"), StandardCharsets.UTF_8));
        }
        assertThrows(IOException.class,
                () -> GocryptFs.open(cipherDir, PASSWORD.toCharArray()),
                "old password should no longer work");
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

    private Path writePassfile() throws IOException {
        Path p = tmp.resolve("passfile-" + System.nanoTime());
        Files.write(p, PASSWORD.getBytes(StandardCharsets.UTF_8));
        return p;
    }

    private static void assumeGocryptfsBinary() throws InterruptedException, IOException {
        boolean haveBinary;
        try {
            Process p = new ProcessBuilder("gocryptfs", "-version")
                    .redirectErrorStream(true).start();
            haveBinary = p.waitFor() == 0;
        } catch (IOException e) {
            haveBinary = false;
        }
        assumeTrue(haveBinary, "gocryptfs binary not found on PATH");
    }

    private static void assumeFuse() throws InterruptedException, IOException {
        assumeGocryptfsBinary();
        assumeTrue(Files.exists(Paths.get("/dev/fuse")), "FUSE (/dev/fuse) not available");
    }

    private static ProcessResult run(String... cmd) throws Exception {
        return runWithInput(null, cmd);
    }

    private static ProcessResult runWithInput(byte[] stdin, String... cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        Process p = pb.start();
        if (stdin != null) {
            p.getOutputStream().write(stdin);
            p.getOutputStream().close();
        }
        String out = new String(readAll(p.getInputStream()), StandardCharsets.UTF_8);
        if (!p.waitFor(120, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("command timed out: " + Arrays.toString(cmd));
        }
        return new ProcessResult(p.exitValue(), out);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        while ((n = in.read(chunk)) != -1) {
            buffer.write(chunk, 0, n);
        }
        return buffer.toByteArray();
    }

    private static final class ProcessResult {
        final int exitCode;
        final String output;

        ProcessResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}
