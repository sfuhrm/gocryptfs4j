package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class ScryptTest {

    private static final HexFormat HEX = HexFormat.of();

    /** RFC 7914 test vector #1. */
    @Test
    void rfc7914Vector1() {
        byte[] derived = Keys.scrypt(new byte[0], new byte[0], 16, 1, 1, 64);
        byte[] expected = HEX.parseHex(
                "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                        + "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
        assertArrayEquals(expected, derived);
    }
}
