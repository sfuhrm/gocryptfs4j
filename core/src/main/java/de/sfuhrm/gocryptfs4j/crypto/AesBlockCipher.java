package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;
import java.util.Objects;

/**
 * AES-256 as a stateless {@link BlockCipher}, backed by BouncyCastle's
 * {@link AESEngine}.
 */
public final class AesBlockCipher implements BlockCipher {

    private final AESEngine encrypt = new AESEngine();
    private final AESEngine decrypt = new AESEngine();
    private final byte[] key;

    /**
     * Creates an AES-256 block cipher.
     *
     * @param key the 32-byte AES key
     * @throws NullPointerException if {@code key} is {@code null}
     * @throws IllegalArgumentException if {@code key} is not 32 bytes long
     */
    public AesBlockCipher(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("AES key must be " + Constants.KEY_LEN + " bytes");
        }
        this.key = Arrays.copyOf(key, key.length);
        KeyParameter kp = new KeyParameter(key);
        encrypt.init(true, kp);
        decrypt.init(false, kp);
    }

    @Override
    public void wipe() {
        Arrays.fill(key, (byte) 0);
    }

    @Override
    public int blockSize() {
        return Constants.AES_BLOCK_SIZE;
    }

    /**
     * Encrypts one block.
     *
     * @throws NullPointerException if {@code in} or {@code out} is {@code null}
     */
    @Override
    public void encrypt(byte[] in, int inOff, byte[] out, int outOff) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");
        encrypt.processBlock(in, inOff, out, outOff);
    }

    /**
     * Decrypts one block.
     *
     * @throws NullPointerException if {@code in} or {@code out} is {@code null}
     */
    @Override
    public void decrypt(byte[] in, int inOff, byte[] out, int outOff) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");
        decrypt.processBlock(in, inOff, out, outOff);
    }
}
