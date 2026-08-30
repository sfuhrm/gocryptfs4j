package de.sfuhrm.gocryptfs4j.config;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.fs.ContentCipherType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigFileTest {

    private static final char[] PASSWORD = "secretpw".toCharArray();

    @Test
    void createWithXchachaSetsFlag() {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.XCHACHA20_POLY1305);
        assertTrue(cf.xchacha());
        assertTrue(cf.featureFlags.contains(Constants.FLAG_XCHACHA));
        assertFalse(cf.featureFlags.contains(Constants.FLAG_GCM_IV128));
    }

    @Test
    void createWithAesSivSetsFlag() {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.AES_SIV);
        assertTrue(cf.aessiv());
        assertTrue(cf.featureFlags.contains(Constants.FLAG_AES_SIV));
        assertTrue(cf.featureFlags.contains(Constants.FLAG_GCM_IV128));
        assertFalse(cf.featureFlags.contains(Constants.FLAG_XCHACHA));
    }

    @Test
    void createWithGcmSetsGcmFlag() {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.AES_GCM);
        assertFalse(cf.xchacha());
        assertFalse(cf.aessiv());
        assertTrue(cf.featureFlags.contains(Constants.FLAG_GCM_IV128));
        assertFalse(cf.featureFlags.contains(Constants.FLAG_XCHACHA));
    }

    @ParameterizedTest
    @EnumSource(ContentCipherType.class)
    void masterKeyRoundTrip(ContentCipherType cipherType) throws Exception {
        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
        ConfigFile cf = ConfigFile.create(masterKey, PASSWORD, false, cipherType);

        assertArrayEquals(masterKey, cf.decryptMasterKey(PASSWORD));
    }

    @ParameterizedTest
    @EnumSource(ContentCipherType.class)
    void contentEncUsesConfiguredCipher(ContentCipherType cipherType) throws Exception {
        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
        ConfigFile cf = ConfigFile.create(masterKey, PASSWORD, false, cipherType);

        ContentEnc enc = cf.contentEnc(masterKey);
        int expectedIvLen;
        switch (cipherType) {
            case XCHACHA20_POLY1305:
                expectedIvLen = Constants.XCHACHA_NONCE_LEN;
                break;
            case AES_SIV:
            case AES_GCM:
            default:
                expectedIvLen = Constants.DEFAULT_IV_BITS / 8;
                break;
        }
        assertEquals(expectedIvLen, enc.ivLen);
        assertEquals(expectedIvLen + Constants.AUTH_TAG_LEN, enc.blockOverhead());

        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        byte[] data = new byte[1000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        byte[] ct = enc.encryptBlock(data, 0, fileId);
        assertArrayEquals(data, enc.decryptBlock(ct, 0, fileId));
    }

    @Test
    void wrongPasswordRejected() throws Exception {
        ConfigFile cf = ConfigFile.create(Keys.randomBytes(Constants.KEY_LEN), PASSWORD, false,
                ContentCipherType.AES_SIV);
        assertTrue(cf.aessiv());
        try {
            cf.decryptMasterKey("wrong".toCharArray());
            org.junit.jupiter.api.Assertions.fail("expected IOException for wrong password");
        } catch (java.io.IOException expected) {
            // ok
        }
    }
}
