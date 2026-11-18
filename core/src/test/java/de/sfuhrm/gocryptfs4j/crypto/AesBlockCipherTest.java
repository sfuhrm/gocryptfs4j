package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import org.bouncycastle.util.encoders.Hex;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesBlockCipherTest {

    @Test
    void knownAnswerEncrypt() {
        byte[] key = Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] plain = Hex.decode("00112233445566778899aabbccddeeff");
        AesBlockCipher cipher = new AesBlockCipher(key);

        byte[] out = new byte[16];
        cipher.encrypt(plain, 0, out, 0);

        assertArrayEquals(Hex.decode("8ea2b7ca516745bfeafc49904b496089"), out);
    }

    @Test
    void knownAnswerDecrypt() {
        byte[] key = Hex.decode(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] ciphertext = Hex.decode("8ea2b7ca516745bfeafc49904b496089");
        AesBlockCipher cipher = new AesBlockCipher(key);

        byte[] out = new byte[16];
        cipher.decrypt(ciphertext, 0, out, 0);

        assertArrayEquals(Hex.decode("00112233445566778899aabbccddeeff"), out);
    }

    @Test
    void blockSizeIs16() {
        assertEquals(Constants.AES_BLOCK_SIZE, new AesBlockCipher(new byte[32]).blockSize());
    }

    @Test
    void roundTrip() {
        byte[] key = Keys.randomBytes(Constants.KEY_LEN);
        byte[] plain = Keys.randomBytes(Constants.AES_BLOCK_SIZE);
        AesBlockCipher cipher = new AesBlockCipher(key);

        byte[] enc = new byte[16];
        cipher.encrypt(plain, 0, enc, 0);
        byte[] dec = new byte[16];
        cipher.decrypt(enc, 0, dec, 0);

        assertArrayEquals(plain, dec);
    }

    @Test
    void concurrentUseIsSafe() throws Exception {
        byte[] key = Keys.randomBytes(Constants.KEY_LEN);
        byte[] plain = Keys.randomBytes(Constants.AES_BLOCK_SIZE);
        AesBlockCipher cipher = new AesBlockCipher(key);
        byte[] expected = new byte[Constants.AES_BLOCK_SIZE];
        cipher.encrypt(plain, 0, expected, 0);

        int threads = 8;
        int iterations = 2000;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        try {
            for (int t = 0; t < threads; t++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    byte[] out = new byte[Constants.AES_BLOCK_SIZE];
                    byte[] dec = new byte[Constants.AES_BLOCK_SIZE];
                    for (int i = 0; i < iterations; i++) {
                        cipher.encrypt(plain, 0, out, 0);
                        if (!Arrays.equals(expected, out)) {
                            throw new AssertionError("concurrent encryption corrupted");
                        }
                        cipher.decrypt(out, 0, dec, 0);
                        if (!Arrays.equals(plain, dec)) {
                            throw new AssertionError("concurrent decryption corrupted");
                        }
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void rejectsWrongKeyLength() {
        assertThrows(IllegalArgumentException.class, () -> new AesBlockCipher(new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> new AesBlockCipher(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> new AesBlockCipher(new byte[0]));
    }

    @Test
    void wipeMakesCipherUnusable() {
        byte[] key = Keys.randomBytes(Constants.KEY_LEN);
        AesBlockCipher cipher = new AesBlockCipher(key);
        byte[] in = new byte[Constants.AES_BLOCK_SIZE];
        byte[] out = new byte[Constants.AES_BLOCK_SIZE];

        cipher.wipe();
        cipher.wipe();

        assertThrows(IllegalStateException.class, () -> cipher.encrypt(in, 0, out, 0));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(in, 0, out, 0));
    }
}
