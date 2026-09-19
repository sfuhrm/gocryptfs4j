package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Objects;

/**
 * AES-256 as a stateless {@link BlockCipher}, backed by BouncyCastle's
 * {@link AESEngine}.
 *
 * <p>The key is held only by the underlying engines; this class does not keep
 * its own copy. {@link #wipe()} re-initializes the engines with an all-zero key,
 * and afterwards the instance is unusable: every attempt to encrypt or decrypt
 * throws {@link IllegalStateException}.</p>
 */
public final class AesBlockCipher implements BlockCipher {

    /** The AES engine used for encryption. */
    private final MultiBlockCipher encrypt = AESEngine.newInstance();

    /** The AES engine used for decryption. */
    private final MultiBlockCipher decrypt = AESEngine.newInstance();

    /** Whether this cipher has been wiped. */
    private volatile boolean wiped;

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
        KeyParameter kp = new KeyParameter(key);
        encrypt.init(true, kp);
        decrypt.init(false, kp);
    }

    /**
     * Wipes the underlying key material and makes this cipher unusable. Calling
     * this method more than once has no effect.
     */
    @Override
    public void wipe() {
        if (!wiped) {
            wiped = true;
            // Overwrite the engines' key schedules with an all-zero key; the
            // real key is not retained by this class.
            KeyParameter zero = new KeyParameter(new byte[Constants.KEY_LEN]);
            encrypt.init(true, zero);
            decrypt.init(false, zero);
        }
    }

    /**
     * Returns the block size in bytes.
     *
     * @return the block size, always 16
     */
    @Override
    public int blockSize() {
        return Constants.AES_BLOCK_SIZE;
    }

    /**
     * Encrypts one block.
     *
     * @param in     the input buffer
     * @param inOff  the input offset
     * @param out    the output buffer
     * @param outOff the output offset
     * @throws NullPointerException if {@code in} or {@code out} is {@code null}
     * @throws IllegalStateException if this cipher has been wiped
     */
    @Override
    public void encrypt(byte[] in, int inOff, byte[] out, int outOff) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");
        checkUsable();
        encrypt.processBlock(in, inOff, out, outOff);
    }

    /**
     * Decrypts one block.
     *
     * @param in     the input buffer
     * @param inOff  the input offset
     * @param out    the output buffer
     * @param outOff the output offset
     * @throws NullPointerException if {@code in} or {@code out} is {@code null}
     * @throws IllegalStateException if this cipher has been wiped
     */
    @Override
    public void decrypt(byte[] in, int inOff, byte[] out, int outOff) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");
        checkUsable();
        decrypt.processBlock(in, inOff, out, outOff);
    }

    /**
     * Throws if this cipher has been wiped.
     *
     * @throws IllegalStateException if this cipher has been wiped
     */
    private void checkUsable() {
        if (wiped) {
            throw new IllegalStateException("cipher has been wiped");
        }
    }
}
