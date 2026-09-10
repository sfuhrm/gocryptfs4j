package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class EmeTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void knownAnswerSingleBlock() {
        // From github.com/rfjakob/eme eme_test.go TestEnc16:
        // key = 32 zero bytes, tweak = 16 zero bytes, input = 16 zero bytes.
        byte[] key = new byte[32];
        byte[] tweak = new byte[16];
        byte[] input = new byte[16];

        Eme eme = new Eme(new AesBlockCipher(key));
        byte[] out = eme.encrypt(tweak, input);

        byte[] expected = HEX.parseHex("f1b9ce8ca15a4ba9fb476905434b9fd3");
        assertArrayEquals(expected, out);
    }

    @Test
    void roundTrip() {
        byte[] key = Keys.randomBytes(32);
        byte[] tweak = Keys.randomBytes(16);
        Eme eme = new Eme(new AesBlockCipher(key));

        for (int len = 16; len <= 256; len += 16) {
            byte[] data = Keys.randomBytes(len);
            byte[] enc = eme.encrypt(tweak, data);
            byte[] dec = eme.decrypt(tweak, enc);
            assertArrayEquals(data, dec, "length " + len);
        }
    }
}
