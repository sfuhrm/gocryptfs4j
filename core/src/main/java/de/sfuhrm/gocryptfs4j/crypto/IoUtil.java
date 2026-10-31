package de.sfuhrm.gocryptfs4j.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Bounded stream-reading helper.
 *
 * <p>The ciphertext tree and the config file are attacker-modifiable, so their
 * contents must never be buffered without a size limit. This is a byte-oriented
 * helper: stores supply an {@link InputStream} (or the bytes) and the size
 * limit; a local-filesystem store performs its own regular-file check before
 * opening the stream.</p>
 */
public final class IoUtil {

    /** Prevents instantiation. */
    private IoUtil() {
    }

    /**
     * Reads a stream, refusing to buffer more than {@code maxBytes} bytes.
     *
     * <p>Unlike {@link java.io.InputStream#readAllBytes()}, this never loads an
     * attacker-sized stream fully into memory: it aborts as soon as the limit is
     * exceeded, so a rogue or corrupt input cannot cause an out-of-memory
     * condition.</p>
     *
     * @param in       the stream to read; not closed by this method
     * @param maxBytes the maximum number of bytes to accept
     * @return the stream contents, at most {@code maxBytes} bytes
     * @throws IOException if the stream cannot be read or exceeds {@code maxBytes}
     * @throws NullPointerException if {@code in} is {@code null}
     */
    public static byte[] readBounded(InputStream in, int maxBytes) throws IOException {
        Objects.requireNonNull(in, "in");
        if (maxBytes < 0) {
            throw new IllegalArgumentException("negative limit: " + maxBytes);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > maxBytes) {
                throw new IOException("input too large (limit " + maxBytes + " bytes)");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
