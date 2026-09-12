package de.sfuhrm.gocryptfs4j.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ContentEncTest {

    private static ContentEnc newEnc() {
        return new ContentEnc(Keys.randomBytes(Constants.KEY_LEN), Constants.DEFAULT_IV_BITS / 8);
    }

    @Test
    void blockOverheadIsNoncePlusTag() {
        assertEquals(Constants.DEFAULT_IV_BITS / 8 + Constants.AUTH_TAG_LEN, newEnc().blockOverhead());
    }

    @Test
    void encryptDecryptBlockRoundTrip() throws GeneralSecurityException {
        ContentEnc enc = newEnc();
        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        byte[] data = new byte[1000];
        Arrays.fill(data, (byte) 0x5a);

        byte[] ct = enc.encryptBlock(data, 0, fileId);
        assertEquals(data.length + enc.ivLen + Constants.AUTH_TAG_LEN, ct.length);

        assertArrayEquals(data, enc.decryptBlock(ct, 0, fileId));
    }

    @Test
    void xchachaBlockRoundTrip() throws GeneralSecurityException {
        ContentEnc enc = new ContentEnc(
                new XChaCha20Poly1305(Keys.randomBytes(Constants.KEY_LEN)),
                Constants.XCHACHA_NONCE_LEN);
        assertEquals(Constants.XCHACHA_NONCE_LEN, enc.ivLen);
        assertEquals(Constants.XCHACHA_NONCE_LEN + Constants.AUTH_TAG_LEN, enc.blockOverhead());

        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        byte[] data = new byte[1000];
        Arrays.fill(data, (byte) 0x6b);

        byte[] ct = enc.encryptBlock(data, 0, fileId);
        assertEquals(data.length + enc.ivLen + Constants.AUTH_TAG_LEN, ct.length);
        assertArrayEquals(data, enc.decryptBlock(ct, 0, fileId));
    }

    @Test
    void emptyBlockIsPassedThrough() throws GeneralSecurityException {
        ContentEnc enc = newEnc();
        assertArrayEquals(new byte[0], enc.encryptBlock(new byte[0], 0, null));
        assertArrayEquals(new byte[0], enc.decryptBlock(new byte[0], 0, null));
    }

    @Test
    void allZeroBlockDecryptsToZeroPlaintext() throws GeneralSecurityException {
        ContentEnc enc = newEnc();
        byte[] zero = new byte[(int) enc.cipherBS];
        byte[] pt = enc.decryptBlock(zero, 7, Keys.randomBytes(Constants.HEADER_ID_LEN));
        assertEquals((int) enc.plainBS, pt.length);
        assertArrayEquals(new byte[(int) enc.plainBS], pt);
    }

    @Test
    void encryptRejectsWrongNonceLength() {
        ContentEnc enc = newEnc();
        assertThrows(IllegalArgumentException.class,
                () -> enc.encryptBlock(new byte[]{1}, 0, null, new byte[enc.ivLen - 1]));
    }

    @Test
    void decryptRejectsTooShortBlock() {
        ContentEnc enc = newEnc();
        assertThrows(IllegalArgumentException.class,
                () -> enc.decryptBlock(new byte[enc.ivLen - 1], 0, null));
    }

    @Test
    void decryptRejectsAllZeroNonce() {
        ContentEnc enc = newEnc();
        byte[] ct = new byte[enc.ivLen + Constants.AUTH_TAG_LEN];
        assertThrows(IllegalArgumentException.class,
                () -> enc.decryptBlock(ct, 0, null));
    }

    @Test
    void wrongBlockNumberRejected() throws GeneralSecurityException {
        ContentEnc enc = newEnc();
        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        byte[] ct = enc.encryptBlock(new byte[64], 5, fileId);
        assertThrows(AEADBadTagException.class, () -> enc.decryptBlock(ct, 6, fileId));
    }

    @Test
    void wrongFileIdRejected() throws GeneralSecurityException {
        ContentEnc enc = newEnc();
        byte[] ct = enc.encryptBlock(new byte[64], 0, Keys.randomBytes(Constants.HEADER_ID_LEN));
        assertThrows(AEADBadTagException.class,
                () -> enc.decryptBlock(ct, 0, Keys.randomBytes(Constants.HEADER_ID_LEN)));
    }

    @Test
    void decryptBlocksMultiple() throws GeneralSecurityException {
        ContentEnc enc = newEnc();
        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        int blockCount = 3;
        byte[] data = new byte[(int) (enc.plainBS * blockCount + 500)];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 7);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int b = 0; b < blockCount; b++) {
            byte[] block = new byte[(int) enc.plainBS];
            System.arraycopy(data, b * (int) enc.plainBS, block, 0, (int) enc.plainBS);
            byte[] cipher = enc.encryptBlock(block, b, fileId);
            out.write(cipher, 0, cipher.length);
        }
        byte[] last = Arrays.copyOfRange(data, blockCount * (int) enc.plainBS, data.length);
        byte[] lastCipher = enc.encryptBlock(last, blockCount, fileId);
        out.write(lastCipher, 0, lastCipher.length);

        assertArrayEquals(data, enc.decryptBlocks(out.toByteArray(), 0, fileId));
    }

    @Test
    void bulkEncryptThenBulkDecryptRoundTrip() throws GeneralSecurityException {
        for (boolean withFileId : new boolean[]{false, true}) {
            ContentEnc enc = newEnc();
            byte[] fileId = withFileId ? Keys.randomBytes(Constants.HEADER_ID_LEN) : null;
            int full = (int) enc.plainBS;
            byte[] data = new byte[full * 2 + 500];
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) (i * 13);
            }

            int overhead = enc.ivLen + Constants.AUTH_TAG_LEN;
            byte[] cipher = new byte[data.length + 3 * overhead];
            int cipherLen = enc.encryptBlocks(data, 0, data.length, 0, fileId, cipher, 0);

            byte[] plain = new byte[data.length];
            int n = enc.decryptBlocks(cipher, 0, cipherLen, 0, fileId, plain, 0);

            assertEquals(data.length, n);
            assertArrayEquals(data, Arrays.copyOf(plain, n));
        }
    }

    @Test
    void bulkDecryptAcceptsPerBlockCiphertext() throws GeneralSecurityException {
        ContentEnc enc = newEnc();
        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        int full = (int) enc.plainBS;
        byte[] data = new byte[full + 137];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 29);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] first = enc.encryptBlock(Arrays.copyOfRange(data, 0, full), 0, fileId);
        out.write(first, 0, first.length);
        byte[] second = enc.encryptBlock(Arrays.copyOfRange(data, full, data.length), 1, fileId);
        out.write(second, 0, second.length);
        byte[] cipher = out.toByteArray();

        byte[] plain = new byte[data.length];
        int n = enc.decryptBlocks(cipher, 0, cipher.length, 0, fileId, plain, 0);

        assertEquals(data.length, n);
        assertArrayEquals(data, Arrays.copyOf(plain, n));
    }

    @Test
    void bulkDecryptTreatsAllZeroBlockAsHole() throws GeneralSecurityException {
        ContentEnc enc = newEnc();
        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        byte[] cipher = new byte[(int) (2 * enc.cipherBS)];
        byte[] real = enc.encryptBlock(new byte[(int) enc.plainBS], 0, fileId);
        System.arraycopy(real, 0, cipher, 0, real.length);

        byte[] plain = new byte[(int) (2 * enc.plainBS)];
        int n = enc.decryptBlocks(cipher, 0, cipher.length, 0, fileId, plain, 0);

        assertEquals(plain.length, n);
        assertArrayEquals(new byte[plain.length], plain);
    }

    @Test
    void bulkMethodsHonorOutputOffsets() throws GeneralSecurityException {
        ContentEnc enc = newEnc();
        byte[] fileId = Keys.randomBytes(Constants.HEADER_ID_LEN);
        byte[] data = new byte[(int) enc.plainBS + 64];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 17);
        }
        int overhead = enc.ivLen + Constants.AUTH_TAG_LEN;
        int pad = 11;

        byte[] cipher = new byte[pad + data.length + 2 * overhead];
        int cipherLen = enc.encryptBlocks(data, 0, data.length, 0, fileId, cipher, pad);
        assertEquals(cipher.length, cipherLen + pad);

        byte[] plain = new byte[pad + data.length];
        int n = enc.decryptBlocks(cipher, pad, cipherLen, 0, fileId, plain, pad);
        assertEquals(data.length, n);
        for (int i = 0; i < pad; i++) {
            assertEquals(0, plain[i]);
        }
        assertArrayEquals(data, Arrays.copyOfRange(plain, pad, pad + n));
    }

    @Test
    void plainSizeToCipherSize() {
        ContentEnc enc = newEnc();
        assertEquals(0, enc.plainSizeToCipherSize(0));
        assertEquals(Constants.HEADER_LEN + enc.blockOverhead() + 1, enc.plainSizeToCipherSize(1));
        assertEquals(Constants.HEADER_LEN + enc.cipherBS, enc.plainSizeToCipherSize(enc.plainBS));
    }

    @Test
    void cipherSizeToPlainSize() {
        ContentEnc enc = newEnc();
        assertEquals(0, enc.cipherSizeToPlainSize(0));
        assertEquals(0, enc.cipherSizeToPlainSize(Constants.HEADER_LEN));
        assertEquals(0, enc.cipherSizeToPlainSize(Constants.HEADER_LEN - 1));
        assertEquals(enc.plainBS, enc.cipherSizeToPlainSize(Constants.HEADER_LEN + enc.cipherBS));
        assertEquals(1, enc.cipherSizeToPlainSize(Constants.HEADER_LEN + enc.blockOverhead() + 1));
    }

    @Test
    void sizeTranslationsAreInverse() {
        ContentEnc enc = newEnc();
        for (long plainSize = 1; plainSize <= 20_000; plainSize += 37) {
            assertEquals(plainSize, enc.cipherSizeToPlainSize(enc.plainSizeToCipherSize(plainSize)),
                    "plain size " + plainSize);
        }
    }

    @Test
    void offsetTranslations() {
        ContentEnc enc = newEnc();
        assertEquals(0, enc.plainOffToBlockNo(0));
        assertEquals(0, enc.plainOffToBlockNo(enc.plainBS - 1));
        assertEquals(1, enc.plainOffToBlockNo(enc.plainBS));

        assertEquals(Constants.HEADER_LEN, enc.blockNoToCipherOff(0));
        assertEquals(Constants.HEADER_LEN + enc.cipherBS, enc.blockNoToCipherOff(1));

        assertEquals(0, enc.blockNoToPlainOff(0));
        assertEquals(enc.plainBS, enc.blockNoToPlainOff(1));

        assertEquals(0, enc.cipherOffToBlockNo(Constants.HEADER_LEN));
        assertEquals(1, enc.cipherOffToBlockNo(Constants.HEADER_LEN + enc.cipherBS));
    }

    @Test
    void cipherOffToBlockNoRejectsHeaderOffset() {
        ContentEnc enc = newEnc();
        assertThrows(IllegalArgumentException.class,
                () -> enc.cipherOffToBlockNo(Constants.HEADER_LEN - 1));
    }
}
