package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class KeysTest {

    @Test
    void randomBytesLength() {
        for (int len : new int[]{0, 1, 16, 32, 100}) {
            assertEquals(len, Keys.randomBytes(len).length);
        }
    }

    @Test
    void randomBytesAreRandom() {
        byte[] a = Keys.randomBytes(32);
        byte[] b = Keys.randomBytes(32);
        assertFalse(Arrays.equals(a, b), "two draws of 32 random bytes should differ");
    }

    @Test
    void wipeClearsBuffer() {
        byte[] buf = new byte[16];
        Arrays.fill(buf, (byte) 0x42);
        Keys.wipe(buf);
        assertArrayEquals(new byte[16], buf);
    }

    @Test
    void wipeAcceptsNull() {
        Keys.wipe(null);
    }
}
