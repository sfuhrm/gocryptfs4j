package de.sfuhrm.gocryptfs4j.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * Detects which command-line options the installed {@code gocryptfs} binary
 * supports. gocryptfs gained options over its release history (e.g. {@code -fsck},
 * {@code -xchacha}), so tests that depend on them must be skipped on older
 * releases.
 */
final class GocryptfsCli {

    private static String help;

    private GocryptfsCli() {
    }

    /**
     * Returns whether the installed gocryptfs supports the given option, matched
     * by name (leading dashes and case ignored).
     *
     * @param option the option, e.g. {@code "-xchacha"} or {@code "--fsck"}
     * @return true if the option is advertised in {@code gocryptfs -hh}
     * @throws IOException if the binary cannot be executed
     * @throws InterruptedException if the process is interrupted
     */
    static boolean supports(String option) throws IOException, InterruptedException {
        String name = option.replace("-", "").toLowerCase();
        return help().toLowerCase().contains(name);
    }

    /** Runs {@code gocryptfs -hh} once and caches the full option listing. */
    private static String help() throws IOException, InterruptedException {
        if (help == null) {
            Process p = new ProcessBuilder("gocryptfs", "-hh")
                    .redirectErrorStream(true).start();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            try (InputStream in = p.getInputStream()) {
                while ((n = in.read(chunk)) != -1) {
                    buf.write(chunk, 0, n);
                }
            }
            if (!p.waitFor(30, TimeUnit.SECONDS)) {
                p.destroyForcibly();
            }
            help = new String(buf.toByteArray(), StandardCharsets.UTF_8);
        }
        return help;
    }
}
