package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * A {@link Fido2CommandRunner} that executes an external process, mirroring
 * gocryptfs's own invocation of the libfido2 tools.
 *
 * <p>The tool receives the given lines on standard input and its standard output
 * is captured. Standard error is drained on a separate thread (to avoid pipe
 * deadlocks) and included in the exception when the process exits non-zero.</p>
 *
 * <p>Execution is bounded so that a malfunctioning or malicious tool can neither
 * hang the caller nor exhaust its memory: the process is forcibly terminated
 * when it exceeds the timeout, and standard output and standard error are each
 * capped at {@value #MAX_OUTPUT_BYTES} bytes.</p>
 */
final class ProcessCommandRunner implements Fido2CommandRunner {

    /** Default maximum run time of a FIDO2 tool. */
    private static final long DEFAULT_TIMEOUT_SECONDS = 60;

    /** Grace period between a polite and a forceful termination. */
    private static final long TERMINATION_GRACE_SECONDS = 2;

    /** Maximum number of bytes captured from each of standard output and error. */
    private static final int MAX_OUTPUT_BYTES = 1024 * 1024;

    /** Maximum time to wait for the collector threads to finish, in milliseconds. */
    private static final long JOIN_TIMEOUT_MILLIS = 5000;

    private final long timeout;
    private final TimeUnit timeoutUnit;

    ProcessCommandRunner() {
        this(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    ProcessCommandRunner(long timeout, TimeUnit timeoutUnit) {
        if (timeout <= 0) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        this.timeout = timeout;
        this.timeoutUnit = Objects.requireNonNull(timeoutUnit, "timeoutUnit");
    }

    @Override
    public List<String> run(List<String> command, List<String> stdinLines) throws IOException {
        Process process;
        try {
            process = new ProcessBuilder(command).start();
        } catch (IOException e) {
            throw new IOException("cannot execute " + command.get(0)
                    + " (is libfido2 installed and on PATH?): " + e.getMessage(), e);
        }

        try (InputStream stdoutStream = process.getInputStream();
             InputStream stderrStream = process.getErrorStream()) {
            StreamCollector stdout = new StreamCollector(stdoutStream);
            StreamCollector stderr = new StreamCollector(stderrStream);
            Thread stdoutThread = startCollector(stdout, "fido2-stdout");
            Thread stderrThread = startCollector(stderr, "fido2-stderr");

            try (OutputStream stdin = process.getOutputStream()) {
                writeInput(stdin, stdinLines);
            }

            boolean finished;
            try {
                finished = process.waitFor(timeout, timeoutUnit);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                terminate(process);
                throw new IOException("interrupted while waiting for " + command.get(0), e);
            }

            if (!finished) {
                terminate(process);
                joinQuietly(stdoutThread);
                joinQuietly(stderrThread);
                throw new IOException(command.get(0) + " timed out after " + describeTimeout());
            }

            joinQuietly(stdoutThread);
            joinQuietly(stderrThread);

            if (stdout.isTruncated()) {
                throw new IOException(command.get(0) + " produced too much standard output");
            }

            int exitCode = process.exitValue();
            if (exitCode != 0) {
                String message = stderr.asString().trim();
                if (stderr.isTruncated()) {
                    message = message.isEmpty() ? "(truncated)" : message + " (truncated)";
                }
                throw new IOException(command.get(0) + " exited with code " + exitCode
                        + (message.isEmpty() ? "" : ": " + message));
            }

            return splitLines(stdout.asString());
        } finally {
            if (process.isAlive()) {
                terminate(process);
            }
        }
    }

    private String describeTimeout() {
        return timeout + " " + timeoutUnit.toString().toLowerCase(Locale.ROOT);
    }

    private static void terminate(Process process) {
        process.destroy();
        try {
            if (!process.waitFor(TERMINATION_GRACE_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                process.waitFor(TERMINATION_GRACE_SECONDS, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
    }

    private static Thread startCollector(StreamCollector collector, String name) {
        Thread thread = new Thread(collector, name);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static void writeInput(OutputStream stdin, List<String> stdinLines) {
        try {
            for (String line : stdinLines) {
                stdin.write(line.getBytes(StandardCharsets.UTF_8));
                stdin.write('\n');
            }
        } catch (IOException ignored) {
            // The process may exit without reading all of its input. Ignore the
            // broken pipe, mirroring gocryptfs; the exit status and output are
            // evaluated below.
        }
    }

    private static void joinQuietly(Thread thread) {
        try {
            thread.join(JOIN_TIMEOUT_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static List<String> splitLines(String stdout) {
        List<String> lines = new ArrayList<>();
        for (String line : stdout.split("\n", -1)) {
            lines.add(line.trim());
        }
        return lines;
    }

    /** Drains an input stream into memory, discarding bytes beyond the cap. */
    private static final class StreamCollector implements Runnable {
        private final InputStream in;
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private boolean truncated;

        StreamCollector(InputStream in) {
            this.in = in;
        }

        @Override
        public void run() {
            byte[] buffer = new byte[4096];
            try {
                int read;
                while ((read = in.read(buffer)) != -1) {
                    int remaining = MAX_OUTPUT_BYTES - out.size();
                    if (remaining <= 0) {
                        truncated = true;
                    } else if (read <= remaining) {
                        out.write(buffer, 0, read);
                    } else {
                        out.write(buffer, 0, remaining);
                        truncated = true;
                    }
                }
            } catch (IOException e) {
                // The stream is closed when the process exits or is terminated;
                // nothing useful to do here.
            }
        }

        String asString() {
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }

        boolean isTruncated() {
            return truncated;
        }
    }
}
