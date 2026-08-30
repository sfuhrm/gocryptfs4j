package de.sfuhrm.gocryptfs4j.crypto;

/**
 * Content encryption cipher selection, matching gocryptfs' {@code -init}
 * cipher flags.
 */
public enum ContentCipherType {
    /** AES-256-GCM (the default). */
    AES_GCM,
    /** XChaCha20-Poly1305. */
    XCHACHA20_POLY1305,
    /** AES-SIV (RFC 5297). */
    AES_SIV
}
