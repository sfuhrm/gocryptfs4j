package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GcmTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void knownAnswerNoAad() {
        byte[] key = HEX.parseHex(
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] nonce = HEX.parseHex("cafebabefacedbaddecaf888");
        byte[] plaintext = HEX.parseHex(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c"
                        + "3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

        Gcm gcm = new Gcm(key);
        byte[] out = gcm.encrypt(plaintext, nonce, null);

        assertArrayEquals(HEX.parseHex(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8"
                        + "cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
                        + "b094dac5d93471bdec1a502270e3cc6c"), out);
    }

    @Test
    void knownAnswerWithAad() {
        byte[] key = HEX.parseHex(
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        byte[] nonce = HEX.parseHex("cafebabefacedbaddecaf888");
        byte[] aad = HEX.parseHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] plaintext = HEX.parseHex(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c"
                        + "3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");

        Gcm gcm = new Gcm(key);
        byte[] out = gcm.encrypt(plaintext, nonce, aad);

        assertArrayEquals(HEX.parseHex(
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
}
