package de.sfuhrm.gocryptfs4j.names;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.Eme;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

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

    /**
     * First code point used to escape a non-UTF-8 name byte. Decrypted plaintext
     * names that are not valid UTF-8 are mapped byte-for-byte onto the low
     * surrogate block {@code U+DC00..U+DCFF}, which valid UTF-8 can never
     * produce, so {@link #encodeName(String)} can invert the mapping
     * unambiguously.
     */
    private static final int SURROGATE_ESCAPE_BASE = 0xDC00;

    /** The EME wide-block cipher. */
    private final Eme eme;

    /** The long-name limit in bytes. */
    private final int longNameMax;

    /** Whether long names are hashed. */
    private final boolean longNames;

    /** The base64url encoder. */
    private final Base64.Encoder b64Encoder;

    /** The base64url decoder. */
    private final Base64.Decoder b64Decoder;

    /** Whether deterministic (all-zero) dirivs are used. */
    private final boolean deterministicNames;

    /**
     * Creates a name-transform helper.
     *
     * @param eme                the EME cipher
     * @param longNames          whether long names are hashed
     * @param longNameMax        the long-name limit in bytes
     * @param raw64              whether to use raw (unpadded) base64url
     * @param deterministicNames whether to use a deterministic (all-zero) diriv
     * @throws NullPointerException if {@code eme} is {@code null}
     */
    public NameTransform(Eme eme, boolean longNames, int longNameMax, boolean raw64,
                         boolean deterministicNames) {
        this.eme = Objects.requireNonNull(eme, "eme");
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

    /**
     * Returns the long-name limit in bytes.
     *
     * @return the long-name limit in bytes
     */
    public int longNameMax() {
        return longNameMax;
    }

    /**
     * Encrypts {@code plainName} (EME under {@code iv}) and base64url-encodes it.
     *
     * @param plainName the plaintext name
     * @param iv        the 16-byte directory IV
     * @return the encrypted, base64url-encoded name
     * @throws NullPointerException if {@code plainName} or {@code iv} is {@code null}
     */
    public String encryptName(String plainName, byte[] iv) {
        Objects.requireNonNull(plainName, "plainName");
        Objects.requireNonNull(iv, "iv");
        byte[] bin = encodeName(plainName);
        bin = pad16(bin);
        bin = eme.encrypt(iv, bin);
        return b64Encoder.encodeToString(bin);
    }

    /**
     * Decrypts a base64-encoded cipher name.
     *
     * @param cipherName the ciphertext name
     * @param iv         the 16-byte directory IV
     * @return the plaintext name
     * @throws NullPointerException if {@code cipherName} or {@code iv} is {@code null}
     * @throws IllegalArgumentException if the name is not valid ciphertext
     */
    public String decryptName(String cipherName, byte[] iv) {
        Objects.requireNonNull(cipherName, "cipherName");
        Objects.requireNonNull(iv, "iv");
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
        return decodeName(bin);
    }

    /**
     * Encodes a plaintext name to the raw name bytes gocryptfs stores.
     *
     * <p>Names are normally encoded as UTF-8. A name that came back from
     * {@link #decodeName(byte[])} in the surrogate-escaped form (a non-UTF-8
     * name) is unescaped back to its exact original bytes instead, so listing
     * such a name and then re-resolving it always round-trips.</p>
     *
     * @param name the plaintext name
     * @return the raw name bytes
     * @throws NullPointerException if {@code name} is {@code null}
     */
    public static byte[] encodeName(String name) {
        Objects.requireNonNull(name, "name");
        if (isSurrogateEscaped(name)) {
            byte[] out = new byte[name.length()];
            for (int i = 0; i < name.length(); i++) {
                out[i] = (byte) (name.charAt(i) - SURROGATE_ESCAPE_BASE);
            }
            return out;
        }
        return name.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Decodes raw plaintext name bytes to a Java string, losslessly.
     *
     * <p>Valid UTF-8 is decoded as UTF-8. Any other byte sequence &mdash;
     * legal in gocryptfs, which treats names as opaque byte strings &mdash; is
     * mapped one byte per character onto the low surrogate block
     * {@code U+DC00..U+DCFF}. {@link #encodeName(String)} reverses that
     * mapping, so such a name is never mangled and remains re-resolvable.</p>
     *
     * @param bytes the raw name bytes
     * @return the plaintext name
     * @throws NullPointerException if {@code bytes} is {@code null}
     */
    public static String decodeName(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            StringBuilder sb = new StringBuilder(bytes.length);
            for (byte b : bytes) {
                sb.append((char) (SURROGATE_ESCAPE_BASE + (b & 0xFF)));
            }
            return sb.toString();
        }
    }

    /**
     * Returns whether {@code name} consists solely of surrogate-escape
     * characters ({@code U+DC00..U+DCFF}), i.e. it is the escaped form of a
     * non-UTF-8 name produced by {@link #decodeName(byte[])}.
     *
     * @param name the name to inspect
     * @return {@code true} if the name is surrogate-escaped
     */
    private static boolean isSurrogateEscaped(String name) {
        if (name.isEmpty()) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c < SURROGATE_ESCAPE_BASE || c > SURROGATE_ESCAPE_BASE + 0xFF) {
                return false;
            }
        }
        return true;
    }

    /**
     * Encrypts {@code name} and, if the encrypted form exceeds the long-name
     * limit, hashes it to a {@code gocryptfs.longname.*} name.
     *
     * @param name the plaintext name
     * @param iv   the 16-byte directory IV
     * @return the ciphertext name, possibly hashed
     * @throws NullPointerException if {@code name} or {@code iv} is {@code null}
     */
    public String encryptAndHashName(String name, byte[] iv) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(iv, "iv");
        String cName = encryptName(name, iv);
        if (longNames && cName.length() > longNameMax) {
            return hashLongName(cName);
        }
        return cName;
    }

    /**
     * Returns {@code gocryptfs.longname.[sha256-base64]} for the given cipher name.
     *
     * @param cName the ciphertext name
     * @return the long-name hash
     * @throws NullPointerException if {@code cName} is {@code null}
     */
    public String hashLongName(String cName) {
        Objects.requireNonNull(cName, "cName");
        byte[] hash = sha256(cName.getBytes(StandardCharsets.UTF_8));
        return Constants.LONG_NAME_PREFIX + b64Encoder.encodeToString(hash);
    }

    /**
     * Returns the name type of {@code cName}.
     *
     * @param cName the ciphertext name
     * @return one of {@link #LONG_NAME_CONTENT}, {@link #LONG_NAME_FILENAME} or
     *         {@link #LONG_NAME_NONE}
     * @throws NullPointerException if {@code cName} is {@code null}
     */
    public int nameType(String cName) {
        Objects.requireNonNull(cName, "cName");
        if (!cName.startsWith(Constants.LONG_NAME_PREFIX)) {
            return LONG_NAME_NONE;
        }
        if (cName.endsWith(Constants.LONG_NAME_SUFFIX)) {
            return LONG_NAME_FILENAME;
        }
        return LONG_NAME_CONTENT;
    }

    /**
     * Returns whether {@code cName} is a long-name content store.
     *
     * @param cName the ciphertext name
     * @return true if {@code cName} is a long-name content store
     * @throws NullPointerException if {@code cName} is {@code null}
     */
    public boolean isLongContent(String cName) {
        return nameType(cName) == LONG_NAME_CONTENT;
    }

    /**
     * Returns the content-file name for a ".name" support file.
     *
     * @param cName the ".name" support file name
     * @return the content-file name without the suffix
     * @throws NullPointerException if {@code cName} is {@code null}
     */
    public static String removeLongNameSuffix(String cName) {
        Objects.requireNonNull(cName, "cName");
        return cName.substring(0, cName.length() - Constants.LONG_NAME_SUFFIX.length());
    }

    /**
     * Base64url-encodes {@code data}.
     *
     * @param data the data to encode
     * @return the base64url encoding
     * @throws NullPointerException if {@code data} is {@code null}
     */
    public String b64Encode(byte[] data) {
        Objects.requireNonNull(data, "data");
        return b64Encoder.encodeToString(data);
    }

    /**
     * Base64url-decodes {@code s}.
     *
     * @param s the base64url string
     * @return the decoded bytes
     * @throws NullPointerException if {@code s} is {@code null}
     */
    public byte[] b64Decode(String s) {
        Objects.requireNonNull(s, "s");
        return b64Decoder.decode(s);
    }

    /**
     * Returns the IV to use for name encryption in a directory without a diriv file.
     *
     * @return a 16-byte all-zero IV
     */
    public byte[] zeroDirIV() {
        return new byte[Constants.DIR_IV_LEN];
    }

    /**
     * Returns whether deterministic (all-zero) dirivs are used.
     *
     * @return true if deterministic dirivs are used
     */
    public boolean deterministicNames() {
        return deterministicNames;
    }

    /**
     * Applies PKCS#7 padding to a multiple of the AES block size.
     *
     * @param orig the unpadded data
     * @return the padded data
     */
    static byte[] pad16(byte[] orig) {
        int padLen = Constants.AES_BLOCK_SIZE - orig.length % Constants.AES_BLOCK_SIZE;
        byte[] padded = new byte[orig.length + padLen];
        System.arraycopy(orig, 0, padded, 0, orig.length);
        for (int i = orig.length; i < padded.length; i++) {
            padded[i] = (byte) padLen;
        }
        return padded;
    }

    /**
     * Removes PKCS#7 padding.
     *
     * @param padded the padded data
     * @return the unpadded data
     * @throws IllegalArgumentException if the padding is malformed
     */
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

    /**
     * Computes the SHA-256 digest of the given data.
     *
     * @param data the data to hash
     * @return the 32-byte digest
     * @throws IllegalStateException if SHA-256 is unavailable
     */
    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
