package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FileHeaderTest {

    @Test
    void randomHeaderRoundTrips() {
        FileHeader header = FileHeader.random();

        assertEquals(Constants.CURRENT_VERSION, header.version());
        assertEquals(Constants.HEADER_ID_LEN, header.id().length);

        byte[] packed = header.pack();
        assertEquals(Constants.HEADER_LEN, packed.length);

        FileHeader parsed = FileHeader.parse(packed);
        assertEquals(header.version(), parsed.version());
        assertArrayEquals(header.id(), parsed.id());
    }

    @Test
    void packEncodesVersionBigEndian() {
        byte[] id = new byte[Constants.HEADER_ID_LEN];
        for (int i = 0; i < id.length; i++) {
            id[i] = (byte) (i + 1);
        }

        byte[] packed = new FileHeader(2, id).pack();

        assertEquals(0x00, packed[0] & 0xFF);
        assertEquals(0x02, packed[1] & 0xFF);
        assertArrayEquals(id, Arrays.copyOfRange(packed, Constants.HEADER_VERSION_LEN, Constants.HEADER_LEN));
    }

    @Test
    void parseRejectsWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> FileHeader.parse(new byte[Constants.HEADER_LEN - 1]));
        assertThrows(IllegalArgumentException.class, () -> FileHeader.parse(new byte[Constants.HEADER_LEN + 1]));
    }

    @Test
    void parseRejectsAllZero() {
        assertThrows(IllegalArgumentException.class, () -> FileHeader.parse(new byte[Constants.HEADER_LEN]));
    }

    @Test
    void parseRejectsWrongVersion() {
        byte[] buf = new byte[Constants.HEADER_LEN];
        buf[1] = 0x01; // version 1
        buf[2] = 0x42; // non-zero id byte
        assertThrows(IllegalArgumentException.class, () -> FileHeader.parse(buf));
    }

    @Test
    void parseRejectsZeroId() {
        byte[] buf = new byte[Constants.HEADER_LEN];
        buf[1] = 0x02; // version 2, id all zero
        assertThrows(IllegalArgumentException.class, () -> FileHeader.parse(buf));
    }

    @Test
    void constructorRejectsWrongIdLength() {
        assertThrows(IllegalArgumentException.class, () -> new FileHeader(2, new byte[Constants.HEADER_ID_LEN - 1]));
        assertThrows(IllegalArgumentException.class, () -> new FileHeader(2, new byte[Constants.HEADER_ID_LEN + 1]));
    }
}
