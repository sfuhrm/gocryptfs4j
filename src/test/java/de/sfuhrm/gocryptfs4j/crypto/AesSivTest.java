package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesSivTest {

    private static final HexFormat HEX = HexFormat.of();

    /** RFC 5297 A.1: AES-CMAC-SIV-256, deterministic encryption. */
    @Test
    void rfc5297TestCaseA1() {
        byte[] key = HEX.parseHex(
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] k1 = Arrays.copyOfRange(key, 0, 16);
        byte[] k2 = Arrays.copyOfRange(key, 16, 32);
        byte[] ad = HEX.parseHex(
                "101112131415161718191a1b1c1d1e1f2021222324252627");
        byte[] plaintext = HEX.parseHex("112233445566778899aabbccddee");

        byte[] siv = AesSiv.s2v(k1, new byte[][]{ad}, plaintext);
        assertArrayEquals(HEX.parseHex("85632d07c6e8f37f950acd320a2ecc93"), siv);

        byte[] ct = AesSiv.ctr(k2, siv, plaintext);
        assertArrayEquals(HEX.parseHex("40c02b9690c4dc04daef7f6afe5c"), ct);
    }

    @Test
    void roundTrip() throws GeneralSecurityException {
        AesSiv cipher = new AesSiv(Keys.randomBytes(Constants.SIV_KEY_LEN));

        for (int len : new int[]{0, 1, 14, 16, 17, 1000}) {
            byte[] nonce = Keys.randomBytes(Constants.AES_BLOCK_SIZE);
            byte[] aad = Keys.randomBytes(24);
            byte[] plaintext = Keys.randomBytes(len);

            byte[] ct = cipher.encrypt(plaintext, nonce, aad);
            assertEquals(len + Constants.AES_BLOCK_SIZE, ct.length);
            assertArrayEquals(plaintext, cipher.decrypt(ct, nonce, aad), "length " + len);
        }
    }

    @Test
    void deterministicEncryption() {
        AesSiv cipher = new AesSiv(Keys.randomBytes(Constants.SIV_KEY_LEN));
        byte[] nonce = Keys.randomBytes(Constants.AES_BLOCK_SIZE);
        byte[] aad = Keys.randomBytes(24);
        byte[] plaintext = Keys.randomBytes(100);

        byte[] c1 = cipher.encrypt(plaintext, nonce, aad);
        byte[] c2 = cipher.encrypt(plaintext, nonce, aad);

        assertArrayEquals(c1, c2, "SIV encryption must be deterministic");
    }

    @Test
    void tamperedCiphertextRejected() throws GeneralSecurityException {
        AesSiv cipher = new AesSiv(Keys.randomBytes(Constants.SIV_KEY_LEN));
        byte[] nonce = Keys.randomBytes(Constants.AES_BLOCK_SIZE);
        byte[] ct = cipher.encrypt(Keys.randomBytes(100), nonce, null);

        ct[ct.length / 2] ^= 0x01;

        assertThrows(AEADBadTagException.class, () -> cipher.decrypt(ct, nonce, null));
    }

    @Test
    void wrongAadRejected() throws GeneralSecurityException {
        AesSiv cipher = new AesSiv(Keys.randomBytes(Constants.SIV_KEY_LEN));
        byte[] nonce = Keys.randomBytes(Constants.AES_BLOCK_SIZE);
        byte[] ct = cipher.encrypt(Keys.randomBytes(100), nonce, Keys.randomBytes(8));

        assertThrows(AEADBadTagException.class,
                () -> cipher.decrypt(ct, nonce, Keys.randomBytes(8)));
    }

    @Test
    void rejectsWrongKeyLength() {
        assertThrows(IllegalArgumentException.class, () -> new AesSiv(new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> new AesSiv(new byte[0]));
    }

    @Test
    void rejectsWrongNonceLength() throws GeneralSecurityException {
        AesSiv cipher = new AesSiv(Keys.randomBytes(Constants.SIV_KEY_LEN));
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(new byte[1], new byte[12], null));
        assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(new byte[17], new byte[12], null));
    }
}
