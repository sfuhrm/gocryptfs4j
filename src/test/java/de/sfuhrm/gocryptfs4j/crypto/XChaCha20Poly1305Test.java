package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XChaCha20Poly1305Test {

    @Test
    void roundTrip() throws GeneralSecurityException {
        XChaCha20Poly1305 cipher = new XChaCha20Poly1305(Keys.randomBytes(Constants.KEY_LEN));

        for (int len : new int[]{0, 1, 16, 1000}) {
            byte[] nonce = Keys.randomBytes(Constants.XCHACHA_NONCE_LEN);
            byte[] aad = Keys.randomBytes(16);
            byte[] plaintext = Keys.randomBytes(len);

            byte[] ct = cipher.encrypt(plaintext, nonce, aad);
            assertEquals(len + Constants.AUTH_TAG_LEN, ct.length);
            assertArrayEquals(plaintext, cipher.decrypt(ct, nonce, aad), "length " + len);
        }
    }

    @Test
    void roundTripWithoutAad() throws GeneralSecurityException {
        XChaCha20Poly1305 cipher = new XChaCha20Poly1305(Keys.randomBytes(Constants.KEY_LEN));
        byte[] nonce = Keys.randomBytes(Constants.XCHACHA_NONCE_LEN);
        byte[] plaintext = Keys.randomBytes(64);

        byte[] ct = cipher.encrypt(plaintext, nonce, null);
        assertArrayEquals(plaintext, cipher.decrypt(ct, nonce, null));
    }

    @Test
    void tamperedCiphertextRejected() throws GeneralSecurityException {
        XChaCha20Poly1305 cipher = new XChaCha20Poly1305(Keys.randomBytes(Constants.KEY_LEN));
        byte[] nonce = Keys.randomBytes(Constants.XCHACHA_NONCE_LEN);
        byte[] ct = cipher.encrypt(Keys.randomBytes(100), nonce, null);

        ct[ct.length / 2] ^= 0x01;

        assertThrows(AEADBadTagException.class, () -> cipher.decrypt(ct, nonce, null));
    }

    @Test
    void wrongAadRejected() throws GeneralSecurityException {
        XChaCha20Poly1305 cipher = new XChaCha20Poly1305(Keys.randomBytes(Constants.KEY_LEN));
        byte[] nonce = Keys.randomBytes(Constants.XCHACHA_NONCE_LEN);
        byte[] ct = cipher.encrypt(Keys.randomBytes(100), nonce, Keys.randomBytes(8));

        assertThrows(AEADBadTagException.class, () -> cipher.decrypt(ct, nonce, Keys.randomBytes(8)));
    }

    @Test
    void rejectsWrongKeyLength() {
        assertThrows(IllegalArgumentException.class, () -> new XChaCha20Poly1305(new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> new XChaCha20Poly1305(new byte[0]));
    }

    @Test
    void rejectsWrongNonceLength() throws GeneralSecurityException {
        XChaCha20Poly1305 cipher = new XChaCha20Poly1305(Keys.randomBytes(Constants.KEY_LEN));
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(new byte[1], new byte[12], null));
        assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(new byte[17], new byte[12], null));
    }
}
