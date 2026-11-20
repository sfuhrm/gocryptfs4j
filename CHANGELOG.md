# Changelog

All notable changes to gocryptfs4j are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.2]

Changes since [v0.8.1](https://github.com/sfuhrm/gocryptfs4j/releases/tag/v0.8.1).
This release is dominated by concurrency, crash-safety and key-handling fixes.

### Added

- Write-ahead journal (`CipherJournal`) for crash-consistent writes, including
  appends and header updates, not just overwrites of existing blocks. Journal
  records can carry multiple block updates so a batch or an atomic file growth
  is recovered as one unit.
- `SharedCipherFile` and shared-handle support so multiple channels on the same
  file see coherent data and flush correctly.
- `OpenOptions` to require explicit opt-in for downgraded modes (plaintext names,
  deterministic names) when opening a filesystem.
- `SyncPolicy` to control when buffered plaintext is flushed and forced to disk.
- `GocryptFs.exportMasterKey()` and `formatMasterKey(byte[])` for exporting the
  master key, returning wipeable data.
- Root-level locking (`CipherRootLock`/`RootFileLock`) that no longer creates a
  hidden lock file in the vault's parent directory.
- `SkippedEntryListener` so a single unreadable entry no longer aborts a whole
  directory listing.
- Reserved-name handling for plaintext-names mode.
- `BlockBufferedChannel`, `BlockCache`, `ChannelGuard`, `DirectorySnapshot` and
  `ContentGeometry` as new internal building blocks.
- Documentation for key lifecycle, flush behaviour, scrypt parameters and the
  master key, plus a no-warranty statement.

### Changed

- Key material is wiped on close, including keys of still-open files; AES-GCM and
  HKDF now use BouncyCastle with wipeable key material instead of persistent JCE
  key objects.
- Master key formatting returns `char[]` instead of `String` so it can be wiped.
- Atomic operations based on hard links are now optional.
- Path resolution now follows POSIX behaviour instead of resolving `..`
  lexically before symlinks.
- Configuration validation enforces coherent feature flags and rejects legacy
  filesystems lacking `EMENames`/`GCMIV128`.
- Unbounded internal maps and caches (`dirIvCache`, `fileLocks`, channel maps)
  are now bounded or evicted to avoid memory leaks in long-running processes.
- `Gcm`/`Hkdf` migrated from JCE to BouncyCastle.
- Large writes batch their journal and data commits, amortizing the two fsyncs
  over many blocks instead of paying them per 4 KiB block.
- Module descriptor opens Gson-reflected config packages on the module path.
- README and javadoc updated, including Java 8/module-path notes.

### Fixed

- Crash consistency of directory creation, `diriv` files, small writes, header
  repair and truncation; config and directory metadata are now fsynced.
- Growing a file is atomic: the padded old final block and the new final block
  are committed in one journal record, so a crash no longer leaves a half-grown
  file.
- Durability gaps after `createFile`, `mkdir`, `rename`, `delete` and channel
  close; failed flushes no longer discard data or leave keys wiped.
- Multiple handles on one file overwriting each other, stale caches and data loss
  after sparse writes, writes past EOF, appends across block boundaries, and
  unreadable partial blocks.
- Concurrency and locking: channel I/O bypassing the filesystem lock, I/O while
  holding map locks, races in `Entry.refs`, `copy`/`rename`, `GocryptFs.close()`
  and `AesBlockCipher` thread safety.
- NIO correctness: `truncate(n)` no longer grows a file, `APPEND` is honoured per
  write, file size/listing reflects unflushed data, and compound provider
  operations are atomic.
- Read-only opens and operations no longer write to the cipher directory,
  including failed-close journal recovery, which a read-only instance never
  performs.
- Long-name `.name` contents are verified against the hashed file name.
- Non-UTF-8 and reserved names are handled correctly; NUL bytes and surrogate
  escape validation bypasses are rejected.
- Symlink and TOCTOU gaps in path-based stores; cipher roots that are symlinks no
  longer silently fall back to a plaintext store.
- WatchService instances are closed with the filesystem, blocked `take()` calls
  wake up, and scheduling survives scan errors.
- Resource and descriptor leaks in `FileManager`, `SharedCipherFile.close()` and
  failure cleanup paths; `GocryptFs.create` no longer deletes another owner's
  config on failure.
- Config password bytes are no longer copied unwiped, temp config files use
  restrictive permissions, and hostile configs can no longer force a 512 MiB
  allocation.
- FIDO2 secret quality (length and non-zero) is enforced in core, not only in the
  libfido2 token implementation.
- 2 GB size overflows in `MapCipherStore`.
- Sizing/stat calls and listings no longer use ciphertext size or hide
  `gocryptfs.diriv` where it is an ordinary user file.
- `create-new` semantics no longer depend on a non-atomic `Files.move`.
- Exception handling no longer surfaces unchecked exceptions for I/O failures.
