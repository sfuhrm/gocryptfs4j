package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesSivTest {

    /** RFC 5297 A.1: AES-CMAC-SIV-256, deterministic encryption. */
    @Test
    void rfc5297TestCaseA1() {
        byte[] key = Hex.decode(
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] k1 = Arrays.copyOfRange(key, 0, 16);
        byte[] k2 = Arrays.copyOfRange(key, 16, 32);
        byte[] ad = Hex.decode(
                "101112131415161718191a1b1c1d1e1f2021222324252627");
        byte[] plaintext = Hex.decode("112233445566778899aabbccddee");

        CMac mac = new CMac(AESEngine.newInstance());
        byte[] siv = AesSiv.s2v(k1, new byte[][]{ad}, plaintext, mac);
        assertArrayEquals(Hex.decode("85632d07c6e8f37f950acd320a2ecc93"), siv);

        CTRModeCipher ctr = SICBlockCipher.newInstance(AESEngine.newInstance());
        byte[] ct = AesSiv.ctr(k2, siv, plaintext, ctr);
        assertArrayEquals(Hex.decode("40c02b9690c4dc04daef7f6afe5c"), ct);
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

    @Test
    void wipeMakesCipherUnusable() throws GeneralSecurityException {
        byte[] key = Keys.randomBytes(Constants.SIV_KEY_LEN);
        AesSiv cipher = new AesSiv(key);
        byte[] nonce = Keys.randomBytes(Constants.AES_BLOCK_SIZE);
        byte[] plaintext = Keys.randomBytes(16);

        // Exercise the per-thread scratch ciphers first.
        byte[] ct = cipher.encrypt(plaintext, nonce, null);
        assertArrayEquals(plaintext, cipher.decrypt(ct, nonce, null));

        cipher.wipe();
        cipher.wipe();

        assertThrows(IllegalStateException.class, () -> cipher.encrypt(plaintext, nonce, null));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(ct, nonce, null));

        // The buffer-based overloads must be invalidated as well.
        byte[] out = new byte[plaintext.length + Constants.AES_BLOCK_SIZE];
        assertThrows(IllegalStateException.class, () -> cipher.encrypt(
                plaintext, 0, plaintext.length, nonce, null, 0, 0, out, 0));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(
                ct, 0, ct.length, nonce, null, 0, 0, new byte[plaintext.length], 0));

        // The thread-local scratch was dropped, not left broken: a fresh
        // instance on the same thread still works.
        AesSiv fresh = new AesSiv(key);
        byte[] freshCt = fresh.encrypt(plaintext, nonce, null);
        assertArrayEquals(plaintext, fresh.decrypt(freshCt, nonce, null));
    }

    @Test
    void wipeDoesNotAffectOtherInstances() throws GeneralSecurityException {
        AesSiv first = new AesSiv(Keys.randomBytes(Constants.SIV_KEY_LEN));
        AesSiv second = new AesSiv(Keys.randomBytes(Constants.SIV_KEY_LEN));
        byte[] nonce = Keys.randomBytes(Constants.AES_BLOCK_SIZE);
        byte[] plaintext = Keys.randomBytes(64);

        // Interleave so both instances use the same thread's scratch.
        byte[] secondCt = second.encrypt(plaintext, nonce, null);
        first.encrypt(plaintext, nonce, null);

        first.wipe();

        // Wiping one instance must not disturb the other.
        assertArrayEquals(plaintext, second.decrypt(secondCt, nonce, null));
        assertArrayEquals(secondCt, second.encrypt(plaintext, nonce, null));
    }

    /**
     * Golden vector from gocryptfs {@code internal/siv_aead/correctness_test.go}
     * ({@code TestK64}), which exercises the 64-byte key layout gocryptfs uses
     * for content encryption.
     */
    @Test
    void gocryptfsTestK64() throws GeneralSecurityException {
        byte[] key = new byte[Constants.SIV_KEY_LEN];
        Arrays.fill(key, (byte) 1);
        byte[] nonce = new byte[Constants.AES_BLOCK_SIZE];
        Arrays.fill(nonce, (byte) 2);
        byte[] aad = new byte[24];
        byte[] plaintext = {1, 2, 3, 4, 5, 6, 7, 8, 9};

        AesSiv cipher = new AesSiv(key);
        byte[] out = cipher.encrypt(plaintext, nonce, aad);

        // SIV (16 bytes) followed by ciphertext (9 bytes).
        assertArrayEquals(Hex.decode("317b316f67c3ad336c01c9a01b4c5e552ba89e966bc4c1ade1"), out);
        assertArrayEquals(plaintext, cipher.decrypt(out, nonce, aad));
    }
}
