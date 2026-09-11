/**
 * A {@code java.nio.file} view of a gocryptfs cipher directory.
 *
 * <p>{@link GocryptFsProvider} registers a {@code gocryptfs} URI scheme and
 * exposes the decrypted (plaintext) filesystem through the standard
 * {@code java.nio.file.Files} / {@code Path} API, backed by
 * {@code de.sfuhrm.gocryptfs4j.core.GocryptFs}.</p>
 *
 * <p>The provider is registered as a service, so it can be obtained via
 * {@code FileSystems.newFileSystem}:</p>
 *
 * <pre>{@code
 * import java.net.URI;
 * import java.nio.charset.StandardCharsets;
 * import java.nio.file.FileSystem;
 * import java.nio.file.FileSystems;
 * import java.nio.file.Files;
 * import java.nio.file.Path;
 * import java.nio.file.Paths;
 * import java.util.HashMap;
 * import java.util.Map;
 *
 * Map<String, Object> env = new HashMap<>();
 * env.put("cipherDir", Paths.get("/data/cipher"));   // Path or String
 * env.put("password", "my-password".toCharArray());  // char[]
 *
 * try (FileSystem fs = FileSystems.newFileSystem(URI.create("gocryptfs:///"), env)) {
 *     Path root = fs.getPath("/");
 *
 *     Files.createDirectory(root.resolve("docs"));
 *     Files.write(root.resolve("docs/hello.txt"),
 *             "hello gocryptfs".getBytes(StandardCharsets.UTF_8));
 *
 *     String content = new String(Files.readAllBytes(root.resolve("docs/hello.txt")),
 *             StandardCharsets.UTF_8);
 * }
 * }</pre>
 *
 * <p>Alternatively, instantiate the provider directly with
 * {@link GocryptFsProvider#newFileSystem(Path, char[])}.</p>
 */
package de.sfuhrm.gocryptfs4j.nio;
