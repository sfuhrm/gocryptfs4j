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

    @Test
    void randomBytesFillsExistingBuffer() {
        byte[] buf = new byte[16];
        Keys.randomBytes(buf);
        assertFalse(Arrays.equals(buf, new byte[16]),
                "a 16-byte random draw should not stay all-zero");
    }

    @Test
    void randomBytesRejectsNegativeLength() {
        assertThrows(IllegalArgumentException.class, () -> Keys.randomBytes(-1));
    }

    @Test
    void randomBytesRejectsNullBuffer() {
        assertThrows(NullPointerException.class, () -> Keys.randomBytes((byte[]) null));
    }

    @Test
    void scryptRejectsNullArguments() {
        assertThrows(NullPointerException.class,
                () -> Keys.scrypt(null, new byte[8], 2, 1, 1, 16));
        assertThrows(NullPointerException.class,
                () -> Keys.scrypt(new byte[8], null, 2, 1, 1, 16));
    }

    @Test
    void scryptRejectsInvalidParameters() {
        assertThrows(IllegalArgumentException.class,
                () -> Keys.scrypt(new byte[8], new byte[8], 0, 1, 1, 16));
        assertThrows(IllegalArgumentException.class,
                () -> Keys.scrypt(new byte[8], new byte[8], 2, 0, 1, 16));
        assertThrows(IllegalArgumentException.class,
                () -> Keys.scrypt(new byte[8], new byte[8], 2, 1, 0, 16));
        assertThrows(IllegalArgumentException.class,
                () -> Keys.scrypt(new byte[8], new byte[8], 2, 1, 1, -1));
    }
}
