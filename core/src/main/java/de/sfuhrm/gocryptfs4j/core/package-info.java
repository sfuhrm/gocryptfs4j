/**
 * The public API of gocryptfs4j.
 *
 * <p>This package contains the plain Java API for working with gocryptfs
 * forward-mode cipher directories: {@link GocryptFs} is the central entry point
 * for creating and opening a filesystem, {@link DirEntry} describes a single
 * directory entry, {@link ContentCipherType} selects the content-encryption
 * cipher and {@link CipherFile} provides random-access read/write access to a
 * single encrypted file.</p>
 *
 * <p>A minimal round trip looks like this:</p>
 *
 * <pre>{@code
 * import de.sfuhrm.gocryptfs4j.core.DirEntry;
 * import de.sfuhrm.gocryptfs4j.core.GocryptFs;
 *
 * import java.nio.charset.StandardCharsets;
 * import java.nio.file.Files;
 * import java.nio.file.Path;
 * import java.nio.file.Paths;
 *
 * Path cipherDir = Paths.get("/data/cipher");
 * Files.createDirectories(cipherDir);   // must exist and be empty
 *
 * // Create a new filesystem and write a file.
 * try (GocryptFs fs = GocryptFs.create(cipherDir, "my-password".toCharArray())) {
 *     fs.mkdir("/docs");
 *     fs.createFile("/docs/hello.txt");
 *     fs.write("/docs/hello.txt", 0, "hello gocryptfs".getBytes(StandardCharsets.UTF_8));
 * }
 *
 * // Later, open it again and read back.
 * try (GocryptFs fs = GocryptFs.open(cipherDir, "my-password".toCharArray())) {
 *     for (DirEntry e : fs.list("/docs")) {
 *         System.out.println(e.plainName() + " (" + e.kind() + ", " + e.size() + " bytes)");
 *     }
 *     String content = new String(fs.readAll("/docs/hello.txt"), StandardCharsets.UTF_8);
 * }
 * }</pre>
 *
 * <p>{@link GocryptFs} is {@link AutoCloseable} and wipes the master key and all
 * derived keys from memory on {@link GocryptFs#close() close()}. For use through
 * the standard {@code java.nio.file} API, see the
 * {@code de.sfuhrm.gocryptfs4j.nio} package instead.</p>
 */
package de.sfuhrm.gocryptfs4j.core;
