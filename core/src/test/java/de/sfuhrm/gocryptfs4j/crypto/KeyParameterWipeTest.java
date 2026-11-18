package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Verifies that the wipeable key parameters cached by each cipher are zeroed on
 * {@link ContentCipher#wipe()}.
 */
class KeyParameterWipeTest {

    @Test
    void gcmWipesCachedKey() throws Exception {
        Gcm gcm = new Gcm(Keys.randomBytes(Constants.KEY_LEN));
        KeyParameter key = (KeyParameter) field(gcm, "keyParam").get(gcm);

        gcm.wipe();

        assertArrayEquals(new byte[Constants.KEY_LEN], key.getKey());
    }

    @Test
    void xchachaWipesCachedKey() throws Exception {
        XChaCha20Poly1305 cipher =
                new XChaCha20Poly1305(Keys.randomBytes(Constants.KEY_LEN));
        KeyParameter key = (KeyParameter) field(cipher, "keyParam").get(cipher);

        cipher.wipe();

        assertArrayEquals(new byte[Constants.KEY_LEN], key.getKey());
    }

    @Test
    void aesBlockCipherWipesCachedKey() throws Exception {
        AesBlockCipher cipher = new AesBlockCipher(Keys.randomBytes(Constants.KEY_LEN));
        KeyParameter key = (KeyParameter) field(cipher, "keyParam").get(cipher);

        cipher.wipe();

        assertArrayEquals(new byte[Constants.KEY_LEN], key.getKey());
    }

    @Test
    void aesSivWipesBothCachedKeys() throws Exception {
        AesSiv cipher = new AesSiv(Keys.randomBytes(Constants.SIV_KEY_LEN));
        KeyParameter k1 = (KeyParameter) field(cipher, "k1").get(cipher);
        KeyParameter k2 = (KeyParameter) field(cipher, "k2").get(cipher);

        cipher.wipe();

        assertArrayEquals(new byte[Constants.KEY_LEN], k1.getKey());
        assertArrayEquals(new byte[Constants.KEY_LEN], k2.getKey());
    }

    private static Field field(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }
}
