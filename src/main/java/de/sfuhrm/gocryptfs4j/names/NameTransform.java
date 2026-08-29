package de.sfuhrm.gocryptfs4j.names;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.Eme;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Encrypts and decrypts file names using AES-256-EME with a per-directory IV.
 */
public final class NameTransform {

    /** Value returned by {@link #nameType} for the content store of a long name. */
    public static final int LONG_NAME_CONTENT = 0;
    /** Value returned by {@link #nameType} for the ".name" support file. */
    public static final int LONG_NAME_FILENAME = 1;
    /** Value returned by {@link #nameType} for an ordinary (non-long) name. */
    public static final int LONG_NAME_NONE = 2;

    private final Eme eme;
    private final int longNameMax;
    private final boolean longNames;
    private final Base64.Encoder b64Encoder;
    private final Base64.Decoder b64Decoder;
    private final boolean deterministicNames;

    public NameTransform(Eme eme, boolean longNames, int longNameMax, boolean raw64,
                         boolean deterministicNames) {
        this.eme = eme;
        this.longNames = longNames;
        this.longNameMax = (longNameMax <= 0 || longNameMax > Constants.NAME_MAX)
                ? Constants.NAME_MAX : longNameMax;
        this.deterministicNames = deterministicNames;
        if (raw64) {
            this.b64Encoder = Base64.getUrlEncoder().withoutPadding();
            this.b64Decoder = Base64.getUrlDecoder();
        } else {
            this.b64Encoder = Base64.getUrlEncoder();
            this.b64Decoder = Base64.getUrlDecoder();
        }
    }

    public int longNameMax() {
        return longNameMax;
    }

    /**
     * Encrypts {@code plainName} (EME under {@code iv}) and base64url-encodes it.
     */
    public String encryptName(String plainName, byte[] iv) {
        byte[] bin = plainName.getBytes(StandardCharsets.UTF_8);
        bin = pad16(bin);
        bin = eme.encrypt(iv, bin);
        return b64Encoder.encodeToString(bin);
    }

    /**
     * Decrypts a base64-encoded cipher name.
     *
     * @throws IllegalArgumentException if the name is not valid ciphertext.
     */
    public String decryptName(String cipherName, byte[] iv) {
        byte[] bin;
        try {
            bin = b64Decoder.decode(cipherName);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid base64 in name", e);
        }
        if (bin.length == 0) {
            throw new IllegalArgumentException("empty name");
        }
        if (bin.length % Constants.AES_BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("decoded name length not a multiple of 16");
        }
        bin = eme.decrypt(iv, bin);
        bin = unpad16(bin);
        return new String(bin, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts {@code name} and, if the encrypted form exceeds {@code longNameMax},
     * hashes it to a {@code gocryptfs.longname.*} name.
     */
    public String encryptAndHashName(String name, byte[] iv) {
        String cName = encryptName(name, iv);
        if (longNames && cName.length() > longNameMax) {
            return hashLongName(cName);
        }
        return cName;
    }

    /** Returns {@code gocryptfs.longname.[sha256-base64]}. */
    public String hashLongName(String cName) {
        byte[] hash = sha256(cName.getBytes(StandardCharsets.UTF_8));
        return Constants.LONG_NAME_PREFIX + b64Encoder.encodeToString(hash);
    }

    public int nameType(String cName) {
        if (!cName.startsWith(Constants.LONG_NAME_PREFIX)) {
            return LONG_NAME_NONE;
        }
        if (cName.endsWith(Constants.LONG_NAME_SUFFIX)) {
            return LONG_NAME_FILENAME;
        }
        return LONG_NAME_CONTENT;
    }

    public boolean isLongContent(String cName) {
        return nameType(cName) == LONG_NAME_CONTENT;
    }

    /** Returns the content-file name for a ".name" support file. */
    public static String removeLongNameSuffix(String cName) {
        return cName.substring(0, cName.length() - Constants.LONG_NAME_SUFFIX.length());
    }

    public String b64Encode(byte[] data) {
        return b64Encoder.encodeToString(data);
    }

    public byte[] b64Decode(String s) {
        return b64Decoder.decode(s);
    }

    /** The IV to use for name encryption in a directory without a diriv file. */
    public byte[] zeroDirIV() {
        return new byte[Constants.DIR_IV_LEN];
    }

    public boolean deterministicNames() {
        return deterministicNames;
    }

    /** PKCS#7 padding to a multiple of the AES block size. */
    static byte[] pad16(byte[] orig) {
        int padLen = Constants.AES_BLOCK_SIZE - orig.length % Constants.AES_BLOCK_SIZE;
        byte[] padded = new byte[orig.length + padLen];
        System.arraycopy(orig, 0, padded, 0, orig.length);
        for (int i = orig.length; i < padded.length; i++) {
            padded[i] = (byte) padLen;
        }
        return padded;
    }

    /** Removes PKCS#7 padding. */
    static byte[] unpad16(byte[] padded) {
        if (padded.length == 0) {
            throw new IllegalArgumentException("empty input");
        }
        if (padded.length % Constants.AES_BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("unaligned size");
        }
        int padLen = padded[padded.length - 1] & 0xFF;
        if (padLen == 0 || padLen > Constants.AES_BLOCK_SIZE) {
            throw new IllegalArgumentException("invalid padding length " + padLen);
        }
        if (padLen >= padded.length) {
            throw new IllegalArgumentException("padding too long");
        }
        for (int i = padded.length - padLen; i < padded.length; i++) {
            if ((padded[i] & 0xFF) != padLen) {
                throw new IllegalArgumentException("invalid padding byte");
            }
        }
        byte[] out = new byte[padded.length - padLen];
        System.arraycopy(padded, 0, out, 0, out.length);
        return out;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
