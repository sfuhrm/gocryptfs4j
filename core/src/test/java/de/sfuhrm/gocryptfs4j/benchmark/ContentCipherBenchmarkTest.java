package de.sfuhrm.gocryptfs4j.benchmark;

import de.sfuhrm.gocryptfs4j.core.ContentCipherType;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentCipherBenchmarkTest {

    @Test
    void benchmarkReturnsOneResultPerCipherInEnumOrder() {
        List<ContentCipherBenchmark.Result> results =
                ContentCipherBenchmark.benchmark(Duration.ofMillis(50));

        ContentCipherType[] types = ContentCipherType.values();
        assertEquals(types.length, results.size());
        for (int i = 0; i < types.length; i++) {
            assertEquals(types[i], results.get(i).type());
        }
    }

    @Test
    void benchmarkReportsPositiveFiniteThroughput() {
        List<ContentCipherBenchmark.Result> results =
                ContentCipherBenchmark.benchmark(Duration.ofMillis(50));

        for (ContentCipherBenchmark.Result r : results) {
            assertTrue(Double.isFinite(r.encryptMiBPerSec()) && r.encryptMiBPerSec() > 0,
                    "encrypt throughput must be positive finite: " + r.encryptMiBPerSec());
            assertTrue(Double.isFinite(r.decryptMiBPerSec()) && r.decryptMiBPerSec() > 0,
                    "decrypt throughput must be positive finite: " + r.decryptMiBPerSec());
        }
    }

    @Test
    void benchmarkRejectsNullDuration() {
        assertThrows(NullPointerException.class, () -> ContentCipherBenchmark.benchmark(null));
    }

    @Test
    void benchmarkRejectsNonPositiveDuration() {
        assertThrows(IllegalArgumentException.class,
                () -> ContentCipherBenchmark.benchmark(Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> ContentCipherBenchmark.benchmark(Duration.ofMillis(-1)));
    }

    @Test
    void resultAccessorsAndToString() {
        ContentCipherBenchmark.Result r = new ContentCipherBenchmark.Result(
                ContentCipherType.AES_SIV, 100.0, 200.0);

        assertEquals(ContentCipherType.AES_SIV, r.type());
        assertEquals(100.0, r.encryptMiBPerSec());
        assertEquals(200.0, r.decryptMiBPerSec());
        assertEquals("AES_SIV: encrypt 100.0 MiB/s, decrypt 200.0 MiB/s", r.toString());
    }
}
