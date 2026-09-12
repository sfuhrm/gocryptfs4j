package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A {@link Fido2CommandRunner} that executes an external process, mirroring
 * gocryptfs's own invocation of the libfido2 tools.
 *
 * <p>The tool receives the given lines on standard input and its standard output
 * is captured. Standard error is drained on a separate thread (to avoid pipe
 * deadlocks) and included in the exception when the process exits non-zero.</p>
 */
final class ProcessCommandRunner implements Fido2CommandRunner {

    @Override
    public List<String> run(List<String> command, List<String> stdinLines) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        Process process;
        try {
            process = processBuilder.start();
        } catch (IOException e) {
            throw new IOException("cannot execute " + command.get(0)
                    + " (is libfido2 installed and on PATH?): " + e.getMessage(), e);
        }

        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        Thread stderrThread = new Thread(() -> copy(process.getErrorStream(), stderr), "fido2-stderr");
        stderrThread.setDaemon(true);
        stderrThread.start();

        try (OutputStream stdin = process.getOutputStream()) {
            for (String line : stdinLines) {
                stdin.write(line.getBytes(StandardCharsets.UTF_8));
                stdin.write('\n');
            }
        } catch (IOException ignored) {
            // The process may exit without reading all of its input. Ignore the
            // broken pipe, mirroring gocryptfs; the exit status and output are
            // evaluated below.
        }

        String stdout = new String(readAll(process.getInputStream()), StandardCharsets.UTF_8);

        int exitCode;
        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroy();
            throw new IOException("interrupted while waiting for " + command.get(0), e);
        }
        joinQuietly(stderrThread);

        if (exitCode != 0) {
            String message = new String(stderr.toByteArray(), StandardCharsets.UTF_8).trim();
            throw new IOException(command.get(0) + " exited with code " + exitCode
                    + (message.isEmpty() ? "" : ": " + message));
        }
        return splitLines(stdout);
    }

    private static byte[] readAll(InputStream in) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copy(in, out);
        return out.toByteArray();
    }

    private static void copy(InputStream in, OutputStream out) {
        byte[] buffer = new byte[4096];
        try {
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        } catch (IOException e) {
            // The pipe is closed when the process exits; nothing useful to do.
        }
    }

    private static void joinQuietly(Thread thread) {
        try {
            thread.join(1000);
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
}
