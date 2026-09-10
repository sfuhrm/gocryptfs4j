package de.sfuhrm.gocryptfs4j.config;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Golden tests that load real {@code gocryptfs.conf} files produced by the
 * reference gocryptfs v0.11 tool (password {@code "test"}).
 *
 * <p>The fixtures live in {@code core/src/test/resources/de/sfuhrm/gocryptfs4j/config/}
 * and are taken verbatim from gocryptfs's
 * {@code internal/configfile/config_test/} directory. They pin compatibility
 * with legacy (non-HKDF) config files.</p>
 */
class GocryptfsConfigGoldenTest {

    private static Path resource(String name) throws Exception {
        return Path.of(Objects.requireNonNull(
                        GocryptfsConfigGoldenTest.class.getResource(
                                "/de/sfuhrm/gocryptfs4j/config/" + name))
                .toURI());
    }

    @Test
    void decryptsGocryptFsV011Config() throws Exception {
        ConfigFile cf = ConfigFile.load(resource("gocryptfs-v0.11.conf"));

        assertEquals(2, cf.version);
        assertTrue(cf.isFeatureFlagSet(Constants.FLAG_GCM_IV128));
        assertTrue(cf.isFeatureFlagSet(Constants.FLAG_DIR_IV));
        assertTrue(cf.isFeatureFlagSet(Constants.FLAG_EME_NAMES));
        assertTrue(cf.isFeatureFlagSet(Constants.FLAG_LONG_NAMES));
        assertFalse(cf.isFeatureFlagSet(Constants.FLAG_HKDF), "v0.11 predates HKDF");

        byte[] masterKey = cf.decryptMasterKey("test".toCharArray());
        assertEquals(Constants.KEY_LEN, masterKey.length);
    }

    @Test
    void decryptsGocryptFsV011PlaintextNamesConfig() throws Exception {
        ConfigFile cf = ConfigFile.load(resource("gocryptfs-v0.11-plaintextnames.conf"));

        assertTrue(cf.plaintextNames());
        assertTrue(cf.isFeatureFlagSet(Constants.FLAG_GCM_IV128));
        assertFalse(cf.isFeatureFlagSet(Constants.FLAG_DIR_IV));
        assertFalse(cf.isFeatureFlagSet(Constants.FLAG_HKDF));

        byte[] masterKey = cf.decryptMasterKey("test".toCharArray());
        assertEquals(Constants.KEY_LEN, masterKey.length);
    }

    @Test
    void rejectsWrongPassword() throws Exception {
        ConfigFile cf = ConfigFile.load(resource("gocryptfs-v0.11.conf"));
        try {
            cf.decryptMasterKey("wrong".toCharArray());
            org.junit.jupiter.api.Assertions.fail("expected IOException for wrong password");
        } catch (java.io.IOException expected) {
            // ok
        }
    }
}
