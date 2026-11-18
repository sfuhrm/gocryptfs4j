package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.jspecify.annotations.Nullable;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * AES-256-GCM helper matching Go's {@code cipher.NewGCMWithNonceSize} with a
 * 16-byte tag and a caller-supplied nonce length.
 *
 * <p>gocryptfs uses 128-bit IVs for file content and (for filesystems created
 * by gocryptfs &ge; v1.3) 128-bit IVs for the master key; pre-v1.3 config files
 * use 96-bit IVs. Both are supported by passing the nonce explicitly.</p>
 */
public final class Gcm implements ContentCipher {

    /** The wipeable AES key parameter, reused for every operation. */
    private final KeyParameter keyParam;

    /** Whether this cipher has been wiped. */
    private volatile boolean wiped;

    /** Guards operations against a concurrent {@link #wipe()}. */
    private final ReentrantReadWriteLock stateLock = new ReentrantReadWriteLock();

    /** A thread-local cipher for encryption, reused because it is not thread-safe. */
    private final TrackedThreadLocal<AEADCipher> encryptCipher = new TrackedThreadLocal<>(
            () -> GCMBlockCipher.newInstance(AESEngine.newInstance()));

    /** A thread-local cipher for decryption, reused because it is not thread-safe. */
    private final TrackedThreadLocal<AEADCipher> decryptCipher = new TrackedThreadLocal<>(
            () -> GCMBlockCipher.newInstance(AESEngine.newInstance()));

    /**
     * Creates an AES-256-GCM instance.
     *
     * @param key the 32-byte AES key
     * @throws NullPointerException if {@code key} is {@code null}
     * @throws IllegalArgumentException if {@code key} is not 32 bytes long
     */
    public Gcm(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("GCM key must be " + Constants.KEY_LEN + " bytes");
        }
        this.keyParam = new KeyParameter(key);
    }

    /**
     * Wipes the key and every scratch cipher created so far, and makes this
     * cipher unusable. Calling this method more than once has no effect.
     *
     * <p>The scratch ciphers are per instance and per thread. All of them, not
     * just the calling thread's, are cleared; see {@link TrackedThreadLocal}.
     * Because the scratch is per instance, wiping this cipher never affects
     * another {@code Gcm} instance.</p>
     *
     * <p>The key parameter is created once and reused for every operation, so no
     * per-operation key copies are left behind. Re-initialising the scratch
     * ciphers with a zero key replaces the key material held inside
     * BouncyCastle's cipher objects.</p>
     */
    @Override
    public void wipe() {
        Lock writeLock = stateLock.writeLock();
        writeLock.lock();
        try {
            if (!wiped) {
                wiped = true;
                Arrays.fill(keyParam.getKey(), (byte) 0);
                // Overwrite every scratch cipher with a zero key so the real key
                // schedule can be garbage-collected. No operation can be using a
                // scratch cipher here because wipe holds the write lock.
                KeyParameter zero = new KeyParameter(new byte[Constants.KEY_LEN]);
                byte[] zeroNonce = new byte[Constants.DEFAULT_IV_BITS / 8];
                encryptCipher.wipeAll(c -> c.init(true,
                        new AEADParameters(zero, Constants.AUTH_TAG_LEN * 8, zeroNonce)));
                decryptCipher.wipeAll(c -> c.init(false,
                        new AEADParameters(zero, Constants.AUTH_TAG_LEN * 8, zeroNonce)));
                Arrays.fill(zero.getKey(), (byte) 0);
            }
        } finally {
            writeLock.unlock();
        }
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

    /**
     * Encrypts {@code plaintext}, returning ciphertext followed by a 16-byte tag.
     *
     * @param plaintext the plaintext to encrypt
     * @param nonce     the nonce (12 or 16 bytes)
     * @param aad       additional authenticated data, or {@code null}
     * @return the ciphertext followed by the 16-byte tag
     * @throws NullPointerException if {@code plaintext} or {@code nonce} is {@code null}
     * @throws IllegalStateException if this cipher has been wiped
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] nonce, byte @Nullable [] aad) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(nonce, "nonce");
        Lock readLock = stateLock.readLock();
        readLock.lock();
        try {
            checkUsable();
            AEADCipher cipher = encryptCipher.get();
            cipher.init(true, new AEADParameters(keyParam,
                    Constants.AUTH_TAG_LEN * 8, nonce, aad));
            checkUsable();
            byte[] out = new byte[cipher.getOutputSize(plaintext.length)];
            int len = cipher.processBytes(plaintext, 0, plaintext.length, out, 0);
            try {
                len += cipher.doFinal(out, len);
            } catch (InvalidCipherTextException e) {
                throw new IllegalStateException("AES-GCM encryption failed", e);
            }
            return out;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Decrypts {@code ciphertext} (which must include the trailing 16-byte tag),
     * verifying the tag and {@code aad}.
     *
     * @param ciphertext the ciphertext including the 16-byte tag
     * @param nonce      the nonce used during encryption
     * @param aad        additional authenticated data, or {@code null}
     * @return the decrypted plaintext
     * @throws javax.crypto.AEADBadTagException (a GeneralSecurityException) on
     *         authentication failure
     * @throws NullPointerException if {@code ciphertext} or {@code nonce} is {@code null}
     * @throws IllegalStateException if this cipher has been wiped
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] nonce, byte @Nullable [] aad) throws GeneralSecurityException {
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(nonce, "nonce");
        Lock readLock = stateLock.readLock();
        readLock.lock();
        try {
            checkUsable();
            AEADCipher cipher = decryptCipher.get();
            cipher.init(false, new AEADParameters(keyParam,
                    Constants.AUTH_TAG_LEN * 8, nonce, aad));
            checkUsable();
            byte[] out = new byte[cipher.getOutputSize(ciphertext.length)];
            int len = cipher.processBytes(ciphertext, 0, ciphertext.length, out, 0);
            try {
                len += cipher.doFinal(out, len);
            } catch (InvalidCipherTextException e) {
                AEADBadTagException ex = new AEADBadTagException("AES-GCM authentication failed");
                ex.initCause(e);
                throw ex;
            }
            return len == out.length ? out : Arrays.copyOf(out, len);
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Encrypts a range, writing the ciphertext and tag into {@code out}.
     *
     * @param in     the input buffer
     * @param inOff  the input offset
     * @param inLen  the number of input bytes
     * @param nonce  the nonce (12 or 16 bytes)
     * @param aad    the additional authenticated data buffer
     * @param aadOff the AAD offset
     * @param aadLen the AAD length
     * @param out    the output buffer
     * @param outOff the output offset
     * @return the number of bytes written (ciphertext plus tag)
     * @throws IllegalStateException if this cipher has been wiped
     */
    @Override
    public int encrypt(byte[] in, int inOff, int inLen, byte[] nonce,
                       byte @Nullable [] aad, int aadOff, int aadLen, byte[] out, int outOff) {
        Lock readLock = stateLock.readLock();
        readLock.lock();
        try {
            checkUsable();
            AEADCipher cipher = encryptCipher.get();
            cipher.init(true, new AEADParameters(keyParam,
                    Constants.AUTH_TAG_LEN * 8, nonce));
            checkUsable();
            if (aadLen > 0) {
                cipher.processAADBytes(aad, aadOff, aadLen);
            }
            int len = cipher.processBytes(in, inOff, inLen, out, outOff);
            try {
                len += cipher.doFinal(out, outOff + len);
            } catch (InvalidCipherTextException e) {
                throw new IllegalStateException("AES-GCM encryption failed", e);
            }
            return len;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Decrypts a range, writing the plaintext into {@code out}.
     *
     * @param in     the input buffer (ciphertext plus tag)
     * @param inOff  the input offset
     * @param inLen  the number of input bytes
     * @param nonce  the nonce used during encryption
     * @param aad    the additional authenticated data buffer
     * @param aadOff the AAD offset
     * @param aadLen the AAD length
     * @param out    the output buffer
     * @param outOff the output offset
     * @return the number of plaintext bytes written
     * @throws GeneralSecurityException on authentication failure
     * @throws IllegalStateException if this cipher has been wiped
     */
    @Override
    public int decrypt(byte[] in, int inOff, int inLen, byte[] nonce,
                       byte @Nullable [] aad, int aadOff, int aadLen, byte[] out, int outOff)
            throws GeneralSecurityException {
        Lock readLock = stateLock.readLock();
        readLock.lock();
        try {
            checkUsable();
            AEADCipher cipher = decryptCipher.get();
            cipher.init(false, new AEADParameters(keyParam,
                    Constants.AUTH_TAG_LEN * 8, nonce));
            checkUsable();
            if (aadLen > 0) {
                cipher.processAADBytes(aad, aadOff, aadLen);
            }
            int len = cipher.processBytes(in, inOff, inLen, out, outOff);
            try {
                len += cipher.doFinal(out, outOff + len);
            } catch (InvalidCipherTextException e) {
                AEADBadTagException ex = new AEADBadTagException("AES-GCM authentication failed");
                ex.initCause(e);
                throw ex;
            }
            return len;
        } finally {
            readLock.unlock();
        }
    }
}
