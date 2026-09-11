/**
 * Throughput benchmark for the supported content ciphers.
 *
 * <p>{@link ContentCipherBenchmark} measures the block-encryption and
 * block-decryption throughput of AES-256-GCM, XChaCha20-Poly1305 and AES-SIV,
 * each over a caller-supplied duration:</p>
 *
 * <pre>{@code
 * import de.sfuhrm.gocryptfs4j.benchmark.ContentCipherBenchmark;
 *
 * import java.time.Duration;
 *
 * for (ContentCipherBenchmark.Result r
 *         : ContentCipherBenchmark.benchmark(Duration.ofSeconds(5))) {
 *     System.out.println(r);
 * }
 * }</pre>
 *
 * <p>It can also be run from the command line with
 * {@code ContentCipherBenchmark [seconds]}.</p>
 */
package de.sfuhrm.gocryptfs4j.benchmark;
