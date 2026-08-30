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
            out.writeBytes(enc.encryptBlock(block, b, fileId));
        }
        byte[] last = Arrays.copyOfRange(data, blockCount * (int) enc.plainBS, data.length);
        out.writeBytes(enc.encryptBlock(last, blockCount, fileId));

        assertArrayEquals(data, enc.decryptBlocks(out.toByteArray(), 0, fileId));
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
