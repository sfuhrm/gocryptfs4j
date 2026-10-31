package de.sfuhrm.gocryptfs4j.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Objects;

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
     * <p>The path must be a regular file (not followed as a symlink), so a FIFO
     * or device masquerading as a config, {@code gocryptfs.diriv} or long-name
     * file cannot block the read forever.</p>
     *
     * @param path     the file to read
     * @param maxBytes the maximum number of bytes to accept
     * @return the file contents, at most {@code maxBytes} bytes
     * @throws IOException if the file cannot be read, is not a regular file, or
     *                     exceeds {@code maxBytes}
     * @throws NullPointerException if {@code path} is {@code null}
     */
    public static byte[] readBounded(Path path, int maxBytes) throws IOException {
        if (maxBytes < 0) {
            throw new IllegalArgumentException("negative limit: " + maxBytes);
        }
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new NoSuchFileException(path.toString());
        }
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("not a regular file: " + path);
        }
        try (InputStream in = Files.newInputStream(path)) {
            return readBounded(in, maxBytes);
        }
    }

    /**
     * Reads a stream, refusing to buffer more than {@code maxBytes} bytes.
     *
     * <p>Unlike {@link java.io.InputStream#readAllBytes()}, this never loads an
     * attacker-sized stream fully into memory: it aborts as soon as the limit is
     * exceeded, so a rogue or corrupt input cannot cause an out-of-memory
     * condition. This is the byte-oriented variant used by non-local stores;
     * {@link #readBounded(Path, int)} adds a regular-file check on top of it.</p>
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
