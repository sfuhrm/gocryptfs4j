package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * AES-256 as a stateless {@link BlockCipher}, backed by BouncyCastle's
 * {@link AESEngine}.
 */
public final class AesBlockCipher implements BlockCipher {

    private final AESEngine encrypt = new AESEngine();
    private final AESEngine decrypt = new AESEngine();

    public AesBlockCipher(byte[] key) {
        if (key.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("AES key must be " + Constants.KEY_LEN + " bytes");
        }
        KeyParameter kp = new KeyParameter(key);
        encrypt.init(true, kp);
        decrypt.init(false, kp);
    }

    @Override
    public int blockSize() {
        return Constants.AES_BLOCK_SIZE;
    }

    @Override
    public void encrypt(byte[] in, int inOff, byte[] out, int outOff) {
        encrypt.processBlock(in, inOff, out, outOff);
    }

    @Override
    public void decrypt(byte[] in, int inOff, byte[] out, int outOff) {
        decrypt.processBlock(in, inOff, out, outOff);
    }
}
