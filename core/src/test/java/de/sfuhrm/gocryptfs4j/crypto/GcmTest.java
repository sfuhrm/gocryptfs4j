package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GcmTest {

    @Test
    void knownAnswerNoAad() {
        byte[] key = Hex.decode(
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] nonce = Hex.decode("cafebabefacedbaddecaf888");
        byte[] plaintext = Hex.decode(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c"
                        + "3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

        Gcm gcm = new Gcm(key);
        byte[] out = gcm.encrypt(plaintext, nonce, null);

        assertArrayEquals(Hex.decode(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8"
                        + "cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
                        + "b094dac5d93471bdec1a502270e3cc6c"), out);
    }

    @Test
    void knownAnswerWithAad() {
        byte[] key = Hex.decode(
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] nonce = Hex.decode("cafebabefacedbaddecaf888");
        byte[] aad = Hex.decode("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] plaintext = Hex.decode(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c"
                        + "3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

        Gcm gcm = new Gcm(key);
        byte[] out = gcm.encrypt(plaintext, nonce, aad);

        assertArrayEquals(Hex.decode(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8"
                        + "cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
                        + "2df7cd675b4f09163b41ebf980a7f638"), out);
    }

    @Test
    void roundTrip() throws GeneralSecurityException {
        byte[] key = Keys.randomBytes(Constants.KEY_LEN);
        Gcm gcm = new Gcm(key);

        for (int nonceLen : new int[]{12, 16}) {
            byte[] nonce = Keys.randomBytes(nonceLen);
            byte[] plaintext = Keys.randomBytes(1000);
            byte[] aad = Keys.randomBytes(20);

            byte[] ct = gcm.encrypt(plaintext, nonce, aad);
            byte[] pt = gcm.decrypt(ct, nonce, aad);
            assertArrayEquals(plaintext, pt, "nonce length " + nonceLen);
        }
    }

    @Test
    void tamperedCiphertextRejected() throws GeneralSecurityException {
        Gcm gcm = new Gcm(Keys.randomBytes(Constants.KEY_LEN));
        byte[] nonce = Keys.randomBytes(12);
        byte[] ct = gcm.encrypt(Keys.randomBytes(100), nonce, null);

        ct[ct.length / 2] ^= 0x01;

        assertThrows(AEADBadTagException.class, () -> gcm.decrypt(ct, nonce, null));
    }

    @Test
    void wrongAadRejected() throws GeneralSecurityException {
        Gcm gcm = new Gcm(Keys.randomBytes(Constants.KEY_LEN));
        byte[] nonce = Keys.randomBytes(12);
        byte[] ct = gcm.encrypt(Keys.randomBytes(100), nonce, Keys.randomBytes(8));

        assertThrows(AEADBadTagException.class, () -> gcm.decrypt(ct, nonce, Keys.randomBytes(8)));
    }

    @Test
    void rejectsWrongKeyLength() {
        assertThrows(IllegalArgumentException.class, () -> new Gcm(new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> new Gcm(new byte[0]));
    }

    @Test
    void wipeMakesCipherUnusable() throws GeneralSecurityException {
        byte[] key = Keys.randomBytes(Constants.KEY_LEN);
        Gcm gcm = new Gcm(key);
        byte[] nonce = Keys.randomBytes(12);
        byte[] plaintext = Keys.randomBytes(16);
        byte[] ct = gcm.encrypt(plaintext, nonce, null);

        gcm.wipe();
        gcm.wipe();

        assertThrows(IllegalStateException.class, () -> gcm.encrypt(plaintext, nonce, null));
        assertThrows(IllegalStateException.class, () -> gcm.decrypt(ct, nonce, null));

        // The buffer-based overloads must be invalidated as well.
        byte[] out = new byte[plaintext.length + Constants.AUTH_TAG_LEN];
        assertThrows(IllegalStateException.class, () -> gcm.encrypt(
                plaintext, 0, plaintext.length, nonce, null, 0, 0, out, 0));
        assertThrows(IllegalStateException.class, () -> gcm.decrypt(
                ct, 0, ct.length, nonce, null, 0, 0, new byte[plaintext.length], 0));

        // A fresh instance on the same thread still works.
        Gcm fresh = new Gcm(key);
        assertArrayEquals(plaintext,
                fresh.decrypt(fresh.encrypt(plaintext, nonce, null), nonce, null));
    }

    @Test
    void wipeInvalidatesCipherForOtherThreads() throws Exception {
        Gcm gcm = new Gcm(Keys.randomBytes(Constants.KEY_LEN));
        byte[] nonce = Keys.randomBytes(12);
        byte[] plaintext = Keys.randomBytes(16);
        CountDownLatch used = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Throwable> unexpected = new AtomicReference<>();
        AtomicBoolean invalidated = new AtomicBoolean();

        Thread worker = new Thread(() -> {
            try {
                // Create this thread's scratch cipher before the wipe.
                gcm.encrypt(plaintext, nonce, null);
                used.countDown();
                release.await();
                try {
                    gcm.encrypt(plaintext, nonce, null);
                } catch (IllegalStateException e) {
                    invalidated.set(true);
                }
            } catch (Throwable t) {
                unexpected.set(t);
            }
        });
        worker.start();

        assertTrue(used.await(5, TimeUnit.SECONDS), "worker did not use the cipher");
        gcm.wipe();
        release.countDown();
        worker.join(5000);

        assertFalse(worker.isAlive(), "worker did not finish");
        assertNull(unexpected.get(), () -> "unexpected worker failure: " + unexpected.get());
        assertTrue(invalidated.get(), "wipe must invalidate the cipher for other threads");
    }
}
