package de.sfuhrm.gocryptfs4j.crypto;

/**
 * Constants describing the gocryptfs on-disk format (forward mode).
 *
 * See https://github.com/rfjakob/gocryptfs-website/blob/master/docs/forward_mode_crypto.md
 */
public final class Constants {

    /** Prevents instantiation. */
    private Constants() {
    }

    /** Cipher key length in bytes (all backends use AES-256). */
    public static final int KEY_LEN = 32;

    /** Authentication tag length in bytes (GHASH / Poly1305). */
    public static final int AUTH_TAG_LEN = 16;

    /** AES block size. */
    public static final int AES_BLOCK_SIZE = 16;

    /** Default plaintext block size of file content. */
    public static final int DEFAULT_PLAIN_BS = 4096;

    /** Default IV length in bits (128-bit IVs). */
    public static final int DEFAULT_IV_BITS = 128;

    /** XChaCha20-Poly1305 nonce length in bytes (192-bit extended nonce). */
    public static final int XCHACHA_NONCE_LEN = 24;

    /** AES-SIV key length in bytes (two 256-bit sub-keys). */
    public static final int SIV_KEY_LEN = 64;

    /** Length of a per-directory IV. */
    public static final int DIR_IV_LEN = 16;

    /** File name of the per-directory IV. */
    public static final String DIR_IV_FILENAME = "gocryptfs.diriv";

    /** Default configuration file name. */
    public static final String CONF_DEFAULT_NAME = "gocryptfs.conf";

    /** Per-file header: version (uint16 big endian) + 128-bit random file id. */
    public static final int HEADER_VERSION_LEN = 2;

    /** Length of the per-file header id in bytes. */
    public static final int HEADER_ID_LEN = 16;

    /** Total per-file header length in bytes. */
    public static final int HEADER_LEN = HEADER_VERSION_LEN + HEADER_ID_LEN;

    /** Current on-disk format version. */
    public static final int CURRENT_VERSION = 2;

    /** Prefix used for long (hashed) file names. */
    public static final String LONG_NAME_PREFIX = "gocryptfs.longname.";

    /** Suffix used for long (hashed) file names. */
    public static final String LONG_NAME_SUFFIX = ".name";

    /** Maximum length (in bytes) of a plaintext file name. */
    public static final int NAME_MAX = 255;

    /**
     * Maximum accepted size in bytes of a {@code *.name} long-name file. The
     * stored base64 cipher name is well below this (EME input is capped at
     * 128 blocks, so the base64 form is at most ~2732 bytes).
     */
    public static final int LONG_NAME_CONTENT_MAX_SIZE = 4096;

    /** HKDF info string for the EME filename-encryption sub-key. */
    public static final String HKDF_INFO_EME_NAMES = "EME filename encryption";

    /** HKDF info string for the AES-GCM content-encryption sub-key. */
    public static final String HKDF_INFO_GCM_CONTENT = "AES-GCM file content encryption";

    /** HKDF info string for the AES-SIV content-encryption sub-key. */
    public static final String HKDF_INFO_SIV_CONTENT = "AES-SIV file content encryption";

    /** HKDF info string for the XChaCha20-Poly1305 content-encryption sub-key. */
    public static final String HKDF_INFO_XCHACHA_CONTENT = "XChaCha20-Poly1305 file content encryption";

    /** Feature flag names as stored in gocryptfs.conf. */
    public static final String FLAG_PLAINTEXT_NAMES = "PlaintextNames";

    /** Feature flag: per-directory IVs for name encryption. */
    public static final String FLAG_DIR_IV = "DirIV";

    /** Feature flag: EME wide-block name encryption. */
    public static final String FLAG_EME_NAMES = "EMENames";

    /** Feature flag: 128-bit GCM IVs. */
    public static final String FLAG_GCM_IV128 = "GCMIV128";

    /** Feature flag: long (hashed) file names. */
    public static final String FLAG_LONG_NAMES = "LongNames";

    /** Feature flag: custom long-name limit. */
    public static final String FLAG_LONG_NAME_MAX = "LongNameMax";

    /** Feature flag: AES-SIV content encryption. */
    public static final String FLAG_AES_SIV = "AESSIV";

    /** Feature flag: raw (unpadded) base64url name encoding. */
    public static final String FLAG_RAW64 = "Raw64";

    /** Feature flag: HKDF-derived sub-keys. */
    public static final String FLAG_HKDF = "HKDF";

    /** Feature flag: FIDO2-based key protection. */
    public static final String FLAG_FIDO2 = "FIDO2";

    /** Feature flag: XChaCha20-Poly1305 content encryption. */
    public static final String FLAG_XCHACHA = "XChaCha20Poly1305";

    // ------------------------------------------------------------------
    // Bounds for attacker-controlled scrypt parameters (gocryptfs.conf).
    // gocryptfs only validates minimums, so a rogue config could otherwise
    // force an unbounded memory/CPU load when the filesystem is opened.
    // ------------------------------------------------------------------

    /** Minimum accepted scrypt logN (2^10), matching gocryptfs. */
    public static final int SCRYPT_MIN_LOG_N = 10;

    /** Maximum accepted scrypt logN (2^20). */
    public static final int SCRYPT_MAX_LOG_N = 20;

    /** Minimum accepted scrypt block-size parameter R, matching gocryptfs. */
    public static final int SCRYPT_MIN_R = 8;

    /** Maximum accepted scrypt block-size parameter R. */
    public static final int SCRYPT_MAX_R = 32;

    /** Minimum accepted scrypt parallelization parameter P. */
    public static final int SCRYPT_MIN_P = 1;

    /** Maximum accepted scrypt parallelization parameter P. */
    public static final int SCRYPT_MAX_P = 16;

    /** Minimum accepted scrypt salt length in bytes, matching gocryptfs. */
    public static final int SCRYPT_MIN_SALT_LEN = 32;

    /** Maximum accepted scrypt salt length in bytes. */
    public static final int SCRYPT_MAX_SALT_LEN = 64;

    /** Maximum accepted scrypt working memory in bytes ({@code 128 * N * R}). */
    public static final long SCRYPT_MAX_MEMORY = 1L << 30;

    /**
     * Maximum accepted size of a {@code gocryptfs.conf} file in bytes. A real
     * config is a few kilobytes; the generous limit bounds the memory an
     * attacker-controlled config file can consume before parsing.
     */
    public static final int CONFIG_MAX_SIZE = 1 << 20;

    /** Maximum accepted FIDO2 credential ID length in bytes. */
    public static final int FIDO2_MAX_CREDENTIAL_ID_LEN = 1024;

    /** Maximum accepted FIDO2 HMAC salt length in bytes. */
    public static final int FIDO2_MAX_HMAC_SALT_LEN = 64;

    /** Maximum number of FIDO2 assertion options accepted from a config. */
    public static final int FIDO2_MAX_ASSERT_OPTIONS = 64;

    /** Maximum length of a single FIDO2 assertion option. */
    public static final int FIDO2_MAX_ASSERT_OPTION_LEN = 1024;
}
