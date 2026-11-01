package de.sfuhrm.gocryptfs4j.names;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests the lossless plaintext-name codec in {@link NameTransform}: valid
 * UTF-8 names decode as UTF-8, while non-UTF-8 names (legal in gocryptfs) are
 * preserved byte-for-byte and remain re-resolvable.
 */
class NameTransformTest {

    @Test
    void validUtf8DecodesAsUtf8() {
        String name = "über-ファイル";

        assertArrayEquals(name.getBytes(StandardCharsets.UTF_8),
                NameTransform.encodeName(name));
        assertEquals(name, NameTransform.decodeName(name.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void asciiRoundTrips() {
        assertArrayEquals("hello.txt".getBytes(StandardCharsets.UTF_8),
                NameTransform.encodeName(NameTransform.decodeName(
                        "hello.txt".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void nonUtf8BytesRoundTripLosslessly() {
        byte[] raw = new byte[] { (byte) 0x00, 0x01, (byte) 0xFF, (byte) 0xFE,
                0x41, (byte) 0xC3, 0x28 };

        String decoded = NameTransform.decodeName(raw);
        byte[] reEncoded = NameTransform.encodeName(decoded);

        assertArrayEquals(raw, reEncoded);
    }

    @Test
    void nonUtf8BytesAreEscapedNotReplaced() {
        byte[] raw = new byte[] { (byte) 0xFF, (byte) 0xFE };

        String decoded = NameTransform.decodeName(raw);

        assertEquals("\uDCFF\uDCFE", decoded);
    }
}
