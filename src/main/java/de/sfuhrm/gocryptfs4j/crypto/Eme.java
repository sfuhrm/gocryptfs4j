package de.sfuhrm.gocryptfs4j.crypto;

/**
 * EME (ECB-Mix-ECB) wide-block encryption, as described by Halevi and Rogaway
 * and implemented by github.com/rfjakob/eme.
 *
 * <p>Used by gocryptfs to encrypt file names with a 128-bit directory IV as
 * tweak. The implementation operates on any input whose length is a positive
 * multiple of the AES block size (16 bytes), up to 2048 bytes.</p>
 */
public final class Eme {

    private final BlockCipher bc;

    public Eme(BlockCipher bc) {
        if (bc.blockSize() != Constants.AES_BLOCK_SIZE) {
            throw new IllegalArgumentException("EME requires a 16-byte block cipher");
        }
        this.bc = bc;
    }

    /** EME-encrypts {@code input} under {@code tweak} (both lengths validated). */
    public byte[] encrypt(byte[] tweak, byte[] input) {
        return transform(tweak, input, true);
    }

    /** EME-decrypts {@code input} under {@code tweak}. */
    public byte[] decrypt(byte[] tweak, byte[] input) {
        return transform(tweak, input, false);
    }

    private byte[] transform(byte[] tweak, byte[] p, boolean encrypt) {
        if (tweak.length != Constants.AES_BLOCK_SIZE) {
            throw new IllegalArgumentException("Tweak must be 16 bytes long");
        }
        if (p.length == 0 || p.length % Constants.AES_BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Data must be a positive multiple of 16 bytes");
        }
        int m = p.length / Constants.AES_BLOCK_SIZE;
        if (m > 16 * 8) {
            throw new IllegalArgumentException("EME operates on at most " + (16 * 8) + " blocks");
        }

        byte[] c = new byte[p.length];
        byte[][] l = tabulateL(m);

        byte[] tmp = new byte[Constants.AES_BLOCK_SIZE];

        // PPPj = AES(Pj ^ L[j])
        for (int j = 0; j < m; j++) {
            xor(tmp, 0, p, j * 16, l[j], 0);
            block(c, j * 16, tmp, 0, encrypt);
        }

        // MP = (xorSum PPPj) ^ T
        byte[] mp = new byte[Constants.AES_BLOCK_SIZE];
        xor(mp, 0, c, 0, tweak, 0);
        for (int j = 1; j < m; j++) {
            xorInPlace(mp, 0, c, j * 16);
        }

        // MC = AES(MP)
        byte[] mc = new byte[Constants.AES_BLOCK_SIZE];
        block(mc, 0, mp, 0, encrypt);

        // M = MP ^ MC
        byte[] mBuf = new byte[Constants.AES_BLOCK_SIZE];
        xor(mBuf, 0, mp, 0, mc, 0);

        // CCCj = PPPj ^ (2^(j-1) * M)
        for (int j = 1; j < m; j++) {
            multByTwo(mBuf);
            xorInPlace(c, j * 16, mBuf, 0);
        }

        // CCC1 = MC ^ T ^ (xorSum CCCj)
        byte[] ccc1 = new byte[Constants.AES_BLOCK_SIZE];
        xor(ccc1, 0, mc, 0, tweak, 0);
        for (int j = 1; j < m; j++) {
            xorInPlace(ccc1, 0, c, j * 16);
        }
        System.arraycopy(ccc1, 0, c, 0, 16);

        // Cj = AES(CCCj) ^ L[j]
        for (int j = 0; j < m; j++) {
            block(tmp, 0, c, j * 16, encrypt);
            xor(tmp, 0, tmp, 0, l[j], 0);
            System.arraycopy(tmp, 0, c, j * 16, 16);
        }

        return c;
    }

    /** L[0] = 2*AES(0); L[i] = 2*L[i-1]. */
    private byte[][] tabulateL(int m) {
        byte[] li = new byte[Constants.AES_BLOCK_SIZE];
        byte[] zero = new byte[Constants.AES_BLOCK_SIZE];
        block(li, 0, zero, 0, true);
        byte[][] table = new byte[m][];
        for (int i = 0; i < m; i++) {
            multByTwo(li);
            table[i] = li.clone();
        }
        return table;
    }

    private void block(byte[] out, int outOff, byte[] in, int inOff, boolean encrypt) {
        if (encrypt) {
            bc.encrypt(in, inOff, out, outOff);
        } else {
            bc.decrypt(in, inOff, out, outOff);
        }
    }

    private static void xor(byte[] out, int outOff, byte[] a, int aOff, byte[] b, int bOff) {
        for (int i = 0; i < 16; i++) {
            out[outOff + i] = (byte) (a[aOff + i] ^ b[bOff + i]);
        }
    }

    private static void xorInPlace(byte[] a, int aOff, byte[] b, int bOff) {
        for (int i = 0; i < 16; i++) {
            a[aOff + i] ^= b[bOff + i];
        }
    }

    /** GF(2^128) multiplication by two, reduction polynomial 0x87. In-place. */
    private static void multByTwo(byte[] x) {
        byte[] in = x.clone();
        int carry = 0;
        for (int j = 0; j < 16; j++) {
            int v = ((in[j] & 0xFF) << 1) | carry;
            x[j] = (byte) v;
            carry = (in[j] & 0x80) != 0 ? 1 : 0;
        }
        if ((in[15] & 0x80) != 0) {
            x[0] ^= (byte) 0x87;
        }
    }
}
