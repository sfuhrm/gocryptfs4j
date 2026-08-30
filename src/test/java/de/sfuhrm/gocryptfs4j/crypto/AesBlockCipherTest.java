package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesBlockCipherTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void knownAnswerEncrypt() {
        byte[] key = HEX.parseHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] plain = HEX.parseHex("00112233445566778899aabbccddeeff");
        AesBlockCipher cipher = new AesBlockCipher(key);

        byte[] out = new byte[16];
        cipher.encrypt(plain, 0, out, 0);

        assertArrayEquals(HEX.parseHex("8ea2b7ca516745bfeafc49904b496089"), out);
    }

    @Test
    void knownAnswerDecrypt() {
        byte[] key = HEX.parseHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] ciphertext = HEX.parseHex("8ea2b7ca516745bfeafc49904b496089");
        AesBlockCipher cipher = new AesBlockCipher(key);

        byte[] out = new byte[16];
        cipher.decrypt(ciphertext, 0, out, 0);

        assertArrayEquals(HEX.parseHex("00112233445566778899aabbccddeeff"), out);
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
