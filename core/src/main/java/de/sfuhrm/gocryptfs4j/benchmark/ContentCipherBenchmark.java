package de.sfuhrm.gocryptfs4j.benchmark;

import de.sfuhrm.gocryptfs4j.core.ContentCipherType;
import de.sfuhrm.gocryptfs4j.crypto.AesSiv;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Gcm;
import de.sfuhrm.gocryptfs4j.crypto.Hkdf;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.crypto.XChaCha20Poly1305;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Measures the block-encryption/decryption throughput of the three content
 * ciphers exposed by {@link ContentCipherType}.
 *
 * <p>Each cipher is exercised through the same {@link ContentEnc} block API the
 * filesystem uses (4 KiB plaintext blocks, per-block nonce, block number and
 * file id as additional authenticated data). Key derivation mirrors
 * {@code ConfigFile#contentEnc}: sub-keys are derived from a single master key
 * with HKDF. The measurement runs for a caller-supplied {@link Duration}.</p>
 *
 * <pre>{@code
 * for (ContentCipherBenchmark.Result r
 *         : ContentCipherBenchmark.benchmark(Duration.ofSeconds(5))) {
 *     System.out.println(r);
 * }
 * }</pre>
 */
public final class ContentCipherBenchmark {

    private ContentCipherBenchmark() {
    }

    /** The measured throughput of a single content cipher. */
    public static final class Result {
        private final ContentCipherType type;
        private final double encryptMiBPerSec;
        private final double decryptMiBPerSec;

        Result(ContentCipherType type, double encryptMiBPerSec, double decryptMiBPerSec) {
            this.type = type;
            this.encryptMiBPerSec = encryptMiBPerSec;
            this.decryptMiBPerSec = decryptMiBPerSec;
        }

        /**
         * Returns the cipher this result was measured for.
         *
         * @return the cipher type
         */
        public ContentCipherType type() {
            return type;
        }

        /**
         * Returns the encryption throughput in mebibytes per second.
         *
         * @return the encryption throughput in MiB/s
         */
        public double encryptMiBPerSec() {
            return encryptMiBPerSec;
        }

        /**
         * Returns the decryption throughput in mebibytes per second.
         *
         * @return the decryption throughput in MiB/s
         */
        public double decryptMiBPerSec() {
            return decryptMiBPerSec;
        }

        @Override
        public String toString() {
            return String.format(Locale.ROOT, "%s: encrypt %.1f MiB/s, decrypt %.1f MiB/s",
                    type, encryptMiBPerSec, decryptMiBPerSec);
        }
    }

    /**
     * Benchmarks all three content ciphers, running each for {@code duration}.
     *
     * @param duration the measurement duration per cipher and direction
     * @return one result per {@link ContentCipherType}, in enum order
     * @throws NullPointerException if {@code duration} is {@code null}
     * @throws IllegalArgumentException if {@code duration} is not positive
     */
    public static List<Result> benchmark(Duration duration) {
        Objects.requireNonNull(duration, "duration");
        long nanos = duration.toNanos();
        if (nanos <= 0) {
            throw new IllegalArgumentException("duration must be positive: " + duration);
        }

        byte[] masterKey = Keys.randomBytes(Constants.KEY_LEN);
        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        long warmupNanos = Math.min(nanos / 4, 1_000_000_000L);

        List<Result> results = new ArrayList<>();
        try {
            for (ContentCipherType type : ContentCipherType.values()) {
                ContentEnc enc = contentEnc(type, masterKey);
                try {
                    // Warm up both directions so the JIT has settled.
                    run(enc, fileId, warmupNanos, true);
                    run(enc, fileId, warmupNanos, false);

                    double encryptMiB = run(enc, fileId, nanos, true);
                    double decryptMiB = run(enc, fileId, nanos, false);
                    results.add(new Result(type, encryptMiB, decryptMiB));
                } finally {
                    enc.wipe();
                }
            }
        } finally {
            Keys.wipe(masterKey);
            Keys.wipe(fileId);
        }
        return results;
    }

    /** Builds the {@link ContentEnc} for a cipher type, mirroring {@code ConfigFile#contentEnc}. */
    private static ContentEnc contentEnc(ContentCipherType type, byte[] masterKey) {
        switch (type) {
            case AES_GCM: {
                byte[] key = Hkdf.derive(masterKey, Constants.HKDF_INFO_GCM_CONTENT,
                        Constants.KEY_LEN);
                try {
                    return new ContentEnc(new Gcm(key), Constants.DEFAULT_IV_BITS / 8,
                            Constants.DEFAULT_PLAIN_BS);
                } finally {
                    Keys.wipe(key);
                }
            }
            case XCHACHA20_POLY1305: {
                byte[] key = Hkdf.derive(masterKey, Constants.HKDF_INFO_XCHACHA_CONTENT,
                        Constants.KEY_LEN);
                try {
                    return new ContentEnc(new XChaCha20Poly1305(key),
                            Constants.XCHACHA_NONCE_LEN, Constants.DEFAULT_PLAIN_BS);
                } finally {
                    Keys.wipe(key);
                }
            }
            case AES_SIV: {
                byte[] key = Hkdf.derive(masterKey, Constants.HKDF_INFO_SIV_CONTENT,
                        Constants.SIV_KEY_LEN);
                try {
                    return new ContentEnc(new AesSiv(key), Constants.AES_BLOCK_SIZE,
                            Constants.DEFAULT_PLAIN_BS);
                } finally {
                    Keys.wipe(key);
                }
            }
            default:
                throw new AssertionError("unknown cipher type: " + type);
        }
    }

    /**
     * Runs encryption (or decryption) of 4 KiB blocks for {@code nanos}
     * nanoseconds and returns the achieved throughput in MiB/s.
     */
    private static double run(ContentEnc enc, byte[] fileId, long nanos, boolean encrypt) {
        byte[] plain = new byte[(int) enc.plainBS];
        byte[] ciphertext = null;
        if (!encrypt) {
            ciphertext = enc.encryptBlock(plain, 0, fileId);
        }

        long bytes = 0;
        long blockNo = 0;
        long start = System.nanoTime();
        long deadline = start + nanos;
        while (System.nanoTime() < deadline) {
            if (encrypt) {
                enc.encryptBlock(plain, blockNo, fileId);
            } else {
                try {
                    enc.decryptBlock(ciphertext, 0, fileId);
                } catch (GeneralSecurityException e) {
                    throw new IllegalStateException("decryption failed", e);
                }
            }
            bytes += enc.plainBS;
            blockNo++;
        }

        double seconds = (System.nanoTime() - start) / 1_000_000_000.0;
        return (bytes / (1024.0 * 1024.0)) / seconds;
    }
}
