package de.sfuhrm.gocryptfs4j.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Bounded file-reading helper.
 *
 * <p>The ciphertext tree and the config file are attacker-modifiable, so files
 * inside them must never be buffered without a size limit.</p>
 */
public final class IoUtil {

    /** Prevents instantiation. */
    private IoUtil() {
    }

    /**
     * Reads a file, refusing to buffer more than {@code maxBytes} bytes.
     *
     * <p>Unlike {@link Files#readAllBytes(Path)}, this never loads an
     * attacker-sized file fully into memory: it aborts as soon as the limit is
     * exceeded, so a rogue or corrupt file cannot cause an out-of-memory
     * condition.</p>
     *
     * @param path     the file to read
     * @param maxBytes the maximum number of bytes to accept
     * @return the file contents, at most {@code maxBytes} bytes
     * @throws IOException if the file cannot be read or exceeds {@code maxBytes}
     * @throws NullPointerException if {@code path} is {@code null}
     */
    public static byte[] readBounded(Path path, int maxBytes) throws IOException {
        if (maxBytes < 0) {
            throw new IllegalArgumentException("negative limit: " + maxBytes);
        }
        try (InputStream in = Files.newInputStream(path)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int total = 0;
            int n;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > maxBytes) {
                    throw new IOException("file too large (limit " + maxBytes
                            + " bytes): " + path);
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }
}
