/**
 * libfido2-backed implementation of
 * {@link de.sfuhrm.gocryptfs4j.fido2.Fido2Token}.
 *
 * <p>This package contains
 * {@link de.sfuhrm.gocryptfs4j.fido2.libfido2.LibFido2Token}, which lets
 * gocryptfs4j read and write gocryptfs {@code -fido2} filesystems by driving the
 * libfido2 command-line tools {@code fido2-cred} and {@code fido2-assert}. It is
 * the Java counterpart of gocryptfs's FIDO2 integration and is byte-compatible
 * with filesystems created by gocryptfs: both use the relying-party ID
 * {@code gocryptfs} and derive the same credential and {@code hmac-secret}.</p>
 *
 * <p>The rest of gocryptfs4j does not depend on this package or on libfido2.
 * FIDO2 support is plugged in by passing a {@code Fido2Token} to
 * {@code GocryptFs.create} and {@code GocryptFs.open}; this module only provides
 * one possible implementation (see
 * {@link de.sfuhrm.gocryptfs4j.fido2.Fido2Token} for others).</p>
 *
 * <h2>Prerequisites</h2>
 * <ul>
 *   <li>The {@code fido2-cred} and {@code fido2-assert} executables must be
 *       installed and either on the {@code PATH} or passed explicitly to
 *       {@link de.sfuhrm.gocryptfs4j.fido2.libfido2.LibFido2Token#LibFido2Token(String, String, String)}.
 *       On Debian/Ubuntu they are shipped by the {@code fido2-tools} package, on
 *       macOS by the {@code libfido2} Homebrew formula.</li>
 *   <li>The security key must support the FIDO2 {@code hmac-secret} extension
 *       (for example a YubiKey 5 or a recent SoloKey).</li>
 *   <li>The FIDO2 device path is required, for example {@code /dev/hidraw5} on
 *       Linux. The available devices can be listed with {@code fido2-token -L}.</li>
 * </ul>
 *
 * <h2>Creating a FIDO2-protected filesystem</h2>
 *
 * <p>{@code create} registers a new credential on the token and stores its
 * credential ID, a random HMAC salt and the assertion options in
 * {@code gocryptfs.conf}. The secret returned by the token protects the master
 * key; no password is involved.</p>
 *
 * <pre>{@code
 * import de.sfuhrm.gocryptfs4j.core.GocryptFs;
 * import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
 * import de.sfuhrm.gocryptfs4j.fido2.libfido2.LibFido2Token;
 *
 * import java.nio.charset.StandardCharsets;
 * import java.nio.file.Files;
 * import java.nio.file.Path;
 * import java.nio.file.Paths;
 *
 * Path cipherDir = Paths.get("/data/cipher");
 * Files.createDirectories(cipherDir);   // must exist and be empty
 *
 * Fido2Token token = new LibFido2Token("/dev/hidraw5");
 * try (GocryptFs fs = GocryptFs.create(cipherDir, token)) {
 *     fs.createFile("/hello.txt");
 *     fs.write("/hello.txt", 0, "hello fido2".getBytes(StandardCharsets.UTF_8));
 * }
 * }</pre>
 *
 * <h2>Opening a FIDO2-protected filesystem</h2>
 *
 * <p>The credential ID, HMAC salt and assertion options are read back from
 * {@code gocryptfs.conf} and handed to the token, so opening only needs the
 * token and the cipher directory:</p>
 *
 * <pre>{@code
 * Fido2Token token = new LibFido2Token("/dev/hidraw5");
 * try (GocryptFs fs = GocryptFs.open(cipherDir, token)) {
 *     byte[] content = fs.readAll("/hello.txt");
 * }
 * }</pre>
 *
 * <h2>PIN-protected tokens and interaction</h2>
 *
 * <p>By default the tools only require a touch. To request a PIN, pass the
 * assertion option {@code pin=true} when creating the filesystem:</p>
 *
 * <pre>{@code
 * try (GocryptFs fs = GocryptFs.create(cipherDir, token, null, false,
 *         ContentCipherType.AES_GCM, Collections.singletonList("pin=true"))) {
 *     // ...
 * }
 * }</pre>
 *
 * <p>The options are stored in the config and passed to every later assertion, so
 * opening needs no extra arguments. If the process has a controlling terminal,
 * the libfido2 tools read the PIN from it; otherwise they read it from standard
 * input, which this adapter does not provide interactively.</p>
 *
 * <p>As in gocryptfs, changing the password of a FIDO2-protected filesystem is
 * not supported: the master key is bound to the token, not to a password.</p>
 *
 * @see de.sfuhrm.gocryptfs4j.fido2.Fido2Token
 * @see de.sfuhrm.gocryptfs4j.fido2.libfido2.LibFido2Token
 */
package de.sfuhrm.gocryptfs4j.fido2.libfido2;
