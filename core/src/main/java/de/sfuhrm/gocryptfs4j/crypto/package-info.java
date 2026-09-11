/**
 * Low-level cryptographic primitives implementing the gocryptfs forward-mode
 * on-disk format.
 *
 * <p>Content encryption operates on 4&nbsp;KiB blocks via {@link ContentEnc},
 * backed by one of three authenticated ciphers implementing {@link ContentCipher}:
 * {@link Gcm} (AES-256-GCM, the default), {@link XChaCha20Poly1305} and
 * {@link AesSiv} (RFC 5297). Filename encryption uses EME wide-block encryption
 * ({@link Eme}) over {@link AesBlockCipher}.</p>
 *
 * <p>Key material is derived with {@link Keys} (scrypt per RFC 7914) and
 * {@link Hkdf} (RFC 5869 sub-keys). {@link FileHeader} describes the per-file
 * header and {@link Constants} the shared on-disk format constants.</p>
 *
 * <p>The classes in this package are implementation details and are not part of
 * the public API; use {@code de.sfuhrm.gocryptfs4j.core.GocryptFs} instead.</p>
 */
package de.sfuhrm.gocryptfs4j.crypto;
