## Why

The content-encryption key (the AES-256-GCM / XChaCha20-Poly1305 / AES-SIV key
derived from the master key) is currently materialised once into a single
shared `ContentEnc` object owned by `GocryptFs`, and its key schedule stays in
memory for the entire lifetime of the filesystem — even after every file,
stream and handle that used it has been closed. Secret key material should not
outlive the resource that requires it.

## What Changes

- Scope content-encryption key material to the resource that requires it: a
  file (`CipherFile`), a stream (the decrypting/encrypting streams from
  `openRead`/`openWrite`) or a handle (`SharedCipherFile`,
  `BlockBufferedChannel`, the NIO `GocryptFsFileChannel`) holds its own copy of
  the derived content key and wipes it when it closes.
- Replace the single long-lived `ContentEnc` shared across `GocryptFs`,
  `FileManager`, `DirectoryManager` and every `CipherFile` with a per-resource
  derivation: each resource derives (or receives) a fresh content key from the
  master key and owns it.
- Keep the raw 32-byte master key owned by `GocryptFs` and wiped only on
  `GocryptFs.close()` (unchanged).
- Keep the EME filename-encryption key owned by `GocryptFs`/`NameManager`
  (unchanged — name encryption is a filesystem-level concern, not a
  file/stream/handle resource).
- Transient uses of the content key that are not tied to a file/stream/handle
  (symlink-target encryption/decryption, long-name `.name` file access) use a
  short-lived `ContentEnc` that is wiped immediately after use.

## Capabilities

### New Capabilities
- `key-material-lifecycle`: governs how and when secret key material is created,
  owned and wiped, tying each piece of derived key material to the resource
  that requires it.

### Modified Capabilities
<!-- none: this repository has no existing specs -->

## Impact

- `core` module: `GocryptFs`, `FileManager`, `DirectoryManager`,
  `NameManager`, `CipherFile`, `SharedCipherFile`, `BlockBufferedChannel`,
  `ConfigFile` (content-key derivation entry point).
- `nio` module: `GocryptFsFileChannel` and related stream adapters.
- No on-disk format or wire compatibility change; the derived keys are
  byte-identical, only their in-memory lifetime changes.
- Slightly higher per-open cost (one HKDF derivation + one AES key schedule per
  opened file/stream/handle) in exchange for a much shorter key-material
  lifetime.
