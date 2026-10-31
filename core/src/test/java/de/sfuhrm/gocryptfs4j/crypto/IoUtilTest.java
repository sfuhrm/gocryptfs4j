package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IoUtilTest {

    @Test
    void readBoundedReadsStream() throws Exception {
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(data, IoUtil.readBounded(new ByteArrayInputStream(data), 100));
    }

    @Test
    void readBoundedRejectsOversizedStream() {
        byte[] data = new byte[101];
        assertThrows(IOException.class,
                () -> IoUtil.readBounded(new ByteArrayInputStream(data), 100));
    }
}
