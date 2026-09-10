package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import org.bouncycastle.util.encoders.Hex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesBlockCipherTest {

    @Test
    void knownAnswerEncrypt() {
        byte[] key = Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] plain = Hex.decode("00112233445566778899aabbccddeeff");
        AesBlockCipher cipher = new AesBlockCipher(key);

        byte[] out = new byte[16];
        cipher.encrypt(plain, 0, out, 0);

        assertArrayEquals(Hex.decode("8ea2b7ca516745bfeafc49904b496089"), out);
    }

    @Test
    void knownAnswerDecrypt() {
        byte[] key = Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] ciphertext = Hex.decode("8ea2b7ca516745bfeafc49904b496089");
        AesBlockCipher cipher = new AesBlockCipher(key);

        byte[] out = new byte[16];
        cipher.decrypt(ciphertext, 0, out, 0);

        assertArrayEquals(Hex.decode("00112233445566778899aabbccddeeff"), out);
    }

    @Test
    void blockSizeIs16() {
        assertEquals(Constants.AES_BLOCK_SIZE, new AesBlockCipher(new byte[32]).blockSize());
    }

    @Test
    void roundTrip() {
        byte[] key = Keys.randomBytes(Constants.KEY_LEN);
        byte[] plain = Keys.randomBytes(Constants.AES_BLOCK_SIZE);
        AesBlockCipher cipher = new AesBlockCipher(key);

        byte[] enc = new byte[16];
        cipher.encrypt(plain, 0, enc, 0);
        byte[] dec = new byte[16];
        cipher.decrypt(enc, 0, dec, 0);

        assertArrayEquals(plain, dec);
    }

    @Test
    void rejectsWrongKeyLength() {
        assertThrows(IllegalArgumentException.class, () -> new AesBlockCipher(new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> new AesBlockCipher(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> new AesBlockCipher(new byte[0]));
    }
}
