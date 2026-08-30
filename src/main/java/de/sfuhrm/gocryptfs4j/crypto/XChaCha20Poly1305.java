package de.sfuhrm.gocryptfs4j.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;

/**
 * XChaCha20-Poly1305 helper matching Go's {@code chacha20poly1305.NewX}: a
 * 24-byte nonce, a 16-byte Poly1305 tag and a 32-byte key, backed by
 * BouncyCastle's {@code XChaCha20Poly1305}.
 */
public final class XChaCha20Poly1305 implements ContentCipher {

    private final KeyParameter key;

    public XChaCha20Poly1305(byte[] key) {
        if (key.length != Constants.KEY_LEN) {
            throw new IllegalArgumentException("XChaCha20-Poly1305 key must be "
                    + Constants.KEY_LEN + " bytes");
        }
        this.key = new KeyParameter(key);
    }

    /** Encrypts {@code plaintext}, returning ciphertext || 16-byte tag. */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] nonce, byte[] aad) {
        if (nonce.length != Constants.XCHACHA_NONCE_LEN) {
            throw new IllegalArgumentException("XChaCha20-Poly1305 nonce must be "
                    + Constants.XCHACHA_NONCE_LEN + " bytes");
        }
        AEADCipher cipher = new org.bouncycastle.crypto.modes.XChaCha20Poly1305();
        cipher.init(true, new AEADParameters(key, Constants.AUTH_TAG_LEN * 8, nonce, aad));
        byte[] out = new byte[cipher.getOutputSize(plaintext.length)];
        int len = cipher.processBytes(plaintext, 0, plaintext.length, out, 0);
        try {
            len += cipher.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("XChaCha20-Poly1305 encryption failed", e);
        }
        return out;
    }

    /** Decrypts {@code ciphertext} (including the 16-byte tag), verifying tag and {@code aad}. */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        if (nonce.length != Constants.XCHACHA_NONCE_LEN) {
            throw new IllegalArgumentException("XChaCha20-Poly1305 nonce must be "
                    + Constants.XCHACHA_NONCE_LEN + " bytes");
        }
        AEADCipher cipher = new org.bouncycastle.crypto.modes.XChaCha20Poly1305();
        cipher.init(false, new AEADParameters(key, Constants.AUTH_TAG_LEN * 8, nonce, aad));
        byte[] out = new byte[cipher.getOutputSize(ciphertext.length)];
        int len = cipher.processBytes(ciphertext, 0, ciphertext.length, out, 0);
        try {
            len += cipher.doFinal(out, len);
        } catch (InvalidCipherTextException e) {
            AEADBadTagException ex = new AEADBadTagException("XChaCha20-Poly1305 authentication failed");
            ex.initCause(e);
            throw ex;
        }
        return out;
    }
}
