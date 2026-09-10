package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class HkdfTest {

    private static final HexFormat HEX = HexFormat.of();

    /** RFC 5869 Appendix A.3: empty salt, empty info, IKM = 0x0b * 22. */
    @Test
    void rfc5869TestVector3() {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        byte[] okm = Hkdf.derive(ikm, "", 42);
        byte[] expected = HEX.parseHex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                        + "9d201395faa4b61a96c8");
        assertArrayEquals(expected, okm);
    }

    @Test
    void knownAnswerEmeInfo() {
        byte[] ikm = HEX.parseHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] okm = Hkdf.derive(ikm, Constants.HKDF_INFO_EME_NAMES, 32);
        assertArrayEquals(HEX.parseHex(
                "59366f708e4d4ed892d6bd6ca0de6e927040808b21bd0e1a2753ea365aeaf6c9"), okm);
    }

    @Test
    void knownAnswerGcmContentInfo() {
        byte[] ikm = HEX.parseHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] okm = Hkdf.derive(ikm, Constants.HKDF_INFO_GCM_CONTENT, 32);
        assertArrayEquals(HEX.parseHex(
                "17df772cfec9d28b9ede3c753d0010ba9f199655acfc3b78dd3b61b5dd5f36c5"), okm);
    }

    @Test
    void outputLengthMatchesRequest() {
        byte[] ikm = {1, 2, 3, 4};
        for (int len : new int[]{0, 1, 16, 31, 32, 33, 64, 100}) {
            assertEquals(len, Hkdf.derive(ikm, "info", len).length);
        }
    }

    /**
     * Golden vectors from gocryptfs {@code internal/cryptocore/hkdf_test.go}
     * ({@code TestHkdfDerive}). These pin the sub-key derivation that defines
     * the on-disk format and must never change.
     */
    @Test
    void gocryptfsMasterKeyVectors() {
        byte[] master0 = new byte[32];
        byte[] master1 = new byte[32];
        Arrays.fill(master1, (byte) 1);

        assertArrayEquals(HEX.parseHex(
                        "9ba3cddd48c6339c6e56ebe85f0281d6e9051be4104176e65cb0f8a6f77ae6b4"),
                Hkdf.derive(master0, Constants.HKDF_INFO_EME_NAMES, 32));
        assertArrayEquals(HEX.parseHex(
                        "e8a2499f48700b954f31de732efd04abce822f5c948e7fbc0896607be0d36d12"),
                Hkdf.derive(master1, Constants.HKDF_INFO_EME_NAMES, 32));
        assertArrayEquals(HEX.parseHex(
                        "9137f2e67a842484137f3c458f357f204c30d7458f94f432fa989be96854a649"),
                Hkdf.derive(master1, Constants.HKDF_INFO_GCM_CONTENT, 32));
        assertArrayEquals(HEX.parseHex(
                        "0bfa5da7d9724d4753269940d36898e2c0f3717c0fee86ada58b5fd6c08cc26c"),
                Hkdf.derive(master1, Constants.HKDF_INFO_SIV_CONTENT, 32));
    }
}
