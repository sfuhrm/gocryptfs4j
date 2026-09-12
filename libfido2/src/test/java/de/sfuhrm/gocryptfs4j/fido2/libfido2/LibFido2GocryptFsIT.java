package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import de.sfuhrm.gocryptfs4j.core.DirEntry;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration test that opens and reads a real, pre-existing gocryptfs
 * {@code -fido2} cipher directory with a real FIDO2 security key.
 *
 * <p>This test cannot run in CI: it needs the actual security key that protects
 * the filesystem (the credential is registered on that key) and the
 * {@code fido2-cred}/{@code fido2-assert} tools on the {@code PATH}. It is
 * therefore <em>disabled by default</em> and only runs when the following
 * system properties are supplied:</p>
 *
 * <ul>
 *   <li>{@code gocryptfs.fido2.device} (required) — the FIDO2 device path, for
 *       example {@code /dev/hidraw5}; list devices with {@code fido2-token -L}.</li>
 *   <li>{@code gocryptfs.fido2.cipherDir} (required) — an existing gocryptfs
 *       {@code -fido2} cipher directory protected by that device.</li>
 *   <li>{@code gocryptfs.fido2.file} (optional) — a plaintext file path inside
 *       the filesystem to read and verify. When omitted, the first regular file
 *       found is read instead.</li>
 * </ul>
 *
 * <p>Run it with, for example:</p>
 *
 * <pre>{@code
 * mvn -pl libfido2 -am verify \
 *     -Dgocryptfs.fido2.device=/dev/hidraw5 \
 *     -Dgocryptfs.fido2.cipherDir=/data/cipher
 * }</pre>
 *
 * <p>Opening the filesystem already exercises the real token: the adapter runs
 * {@code fido2-assert -G -h ...} to obtain the {@code hmac-secret} that unwraps
 * the master key. The test additionally lists the root directory and reads a
 * file so that name and content decryption are covered end to end.</p>
 */
class LibFido2GocryptFsIT {

    private static final String DEVICE_PROPERTY = "gocryptfs.fido2.device";
    private static final String CIPHER_DIR_PROPERTY = "gocryptfs.fido2.cipherDir";
    private static final String FILE_PROPERTY = "gocryptfs.fido2.file";

    @Test
    @Disabled("Can only be tested manually with a FIDO2 compatible device")
    void readsRealFido2ProtectedFilesystem() throws Exception {
        String device = requiredProperty(DEVICE_PROPERTY);
        Path cipherDir = Paths.get(requiredProperty(CIPHER_DIR_PROPERTY));
        assumeTrue(Files.isDirectory(cipherDir),
                CIPHER_DIR_PROPERTY + " is not a directory: " + cipherDir);

        Fido2Token token = new LibFido2Token(device);
        try (GocryptFs fs = GocryptFs.open(cipherDir, token)) {
            List<DirEntry> root = fs.list("/");
            assertNotNull(root);

            String file = System.getProperty(FILE_PROPERTY);
            if (file == null || file.isEmpty()) {
                file = firstRegularFile(fs, "/");
            }
            if (file != null) {
                long expected = fs.size(file);
                long actual = drain(fs.openRead(file));
                assertEquals(expected, actual, "plaintext size of " + file);
            }
        }
    }

    private static String requiredProperty(String name) {
        String value = System.getProperty(name);
        assumeTrue(value != null && !value.trim().isEmpty(),
                "set -D" + name + "=... to run this test");
        return value.trim();
    }

    /** Returns the plaintext path of the first regular file below {@code dir}, or null. */
    private static String firstRegularFile(GocryptFs fs, String dir) throws IOException {
        for (DirEntry entry : fs.list(dir)) {
            String child = dir.equals("/") ? "/" + entry.plainName() : dir + "/" + entry.plainName();
            if (entry.isRegularFile()) {
                return child;
            }
            if (entry.isDirectory()) {
                String found = firstRegularFile(fs, child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static long drain(InputStream in) throws IOException {
        try (InputStream stream = in) {
            long total = 0;
            byte[] buffer = new byte[8192];
            int read;
            while ((read = stream.read(buffer)) != -1) {
                total += read;
            }
            return total;
        }
    }
}
