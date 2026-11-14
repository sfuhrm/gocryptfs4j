# key-material-lifecycle Specification

## Purpose

Defines the lifetime and destruction of secret key material so that every piece
of derived key material is wiped when the resource that requires it is closed.

## Requirements

### Requirement: Content-key material is scoped to the requiring resource

The content-encryption key (the AES-256-GCM, XChaCha20-Poly1305 or AES-SIV key
derived from the master key) SHALL be held independently by each resource that
requires it — a file, a stream or a handle — rather than by one long-lived
object shared across the whole filesystem.

#### Scenario: Two concurrently open files hold independent key material

- **WHEN** two files are opened and kept open at the same time
- **THEN** each file holds its own copy of the derived content-key material

#### Scenario: Master key is not duplicated into resources

- **WHEN** a file, stream or handle is opened
- **THEN** the raw 32-byte master key is not copied into that resource; only
  the derived content-key material is held there

### Requirement: Closing a resource wipes its content-key material

When a file, stream or handle is closed, the derived content-key material it
holds SHALL be wiped (overwritten) so it no longer exists in memory.

#### Scenario: Closing a file wipes its key material

- **WHEN** a file that holds content-key material is closed
- **THEN** that file's copy of the content-key material is overwritten and
  unusable for further encryption or decryption

#### Scenario: Closing a stream wipes its key material

- **WHEN** a decrypting or encrypting stream is closed
- **THEN** the content-key material held by that stream is wiped

#### Scenario: Closing a handle wipes its key material

- **WHEN** a buffered channel or NIO file-channel handle is closed
- **THEN** the content-key material held by that handle is wiped

#### Scenario: Closing a resource leaves other resources usable

- **WHEN** one of several concurrently open resources is closed
- **THEN** the remaining open resources can still encrypt and decrypt using
  their own copies of the key material

### Requirement: The master key is wiped only on filesystem close

The raw 32-byte master key SHALL remain owned by the filesystem instance and
SHALL be wiped only when the filesystem itself is closed.

#### Scenario: Master key survives resource close

- **WHEN** every file, stream and handle is closed but the filesystem remains
  open
- **THEN** the master key is still held by the filesystem and new resources can
  still be opened

#### Scenario: Master key is wiped on filesystem close

- **WHEN** the filesystem is closed
- **THEN** the master key and all remaining derived key material are wiped

### Requirement: Transient content-key uses are wiped after use

Content-key material used for a short-lived operation that is not tied to a
file, stream or handle (for example encrypting or decrypting a symlink target)
SHALL be wiped immediately after the operation completes, including on failure.

#### Scenario: Symlink target encryption wipes its key material

- **WHEN** a symlink target is encrypted or decrypted
- **THEN** the content-key material used for that operation is wiped once the
  operation finishes

#### Scenario: Failed transient operation still wipes key material

- **WHEN** a transient content-key operation fails partway through
- **THEN** any content-key material it created is still wiped

### Requirement: Derived keys remain byte-identical

The change in key-material lifetime SHALL NOT alter the bytes of any derived
key, so files remain interoperable with the gocryptfs on-disk format.

#### Scenario: Ciphertext is unchanged

- **WHEN** the same plaintext is written with the same master key under the new
  lifetime model
- **THEN** the produced ciphertext is identical to the ciphertext produced by
  the previous model
