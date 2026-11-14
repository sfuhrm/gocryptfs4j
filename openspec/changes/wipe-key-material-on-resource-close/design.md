## Context

Today `GocryptFs` derives the content-encryption key once, in the constructor,
and materialises it into a single shared `ContentEnc` (which wraps a
`ContentCipher` — `Gcm`, `XChaCha20Poly1305` or `AesSiv` — holding the key
schedule). That one instance is handed to `FileManager` and `DirectoryManager`,
and `FileManager` passes it to every `CipherFile` it opens. It is wiped only in
`GocryptFs.wipeSecrets()` on `close()`.

Key derivation already exists as `ConfigFile.contentEnc(byte[] masterKey)`,
which derives the content key (HKDF for new filesystems, `copyOf(masterKey)` or
`sha512(masterKey)` for legacy ones), builds a `ContentEnc` around it and wipes
the intermediate `byte[]` in a `finally`. See proposal.md for motivation.

Two constraints shape the design:

1. **One shared backing file per ciphertext path.** `FileManager` already keeps
   a single reference-counted `CipherFile` per path (see
   `SharedCipherFile.Entry`) so that all handles on a file share one file-id
   cache; giving every handle its own `CipherFile` would reintroduce the stale
   file-id corruption the sharing was built to prevent.
2. **The master key must outlive open resources.** `GocryptFs.close()` already
   takes the channel-guard write lock and flushes shared files before wiping,
   so deriving fresh keys from the master key while resources are open is safe.

## Goals / Non-Goals

**Goals:**
- Bind the lifetime of the content key (its key schedule) to the resource that
  uses it, wiping it when that resource closes.
- Keep the master key and the EME name key scoped to `GocryptFs` until close.

**Non-Goals:**
- Changing the on-disk format or any derived-key bytes.
- Reference-counting the master key (out of scope by decision — see proposal).
- Wiping caller-supplied password/`byte[]` inputs (unchanged; callers own those).

## Decisions

### 1. Per-resource content key, derived on demand from the master key

Each `CipherFile` receives (or builds) its own `ContentEnc` and wipes it
(`enc.wipe()`) in `CipherFile.close()`, alongside the existing scratch-buffer
wipe. `CipherFile.open` no longer takes a shared `ContentEnc`; its caller
supplies a fresh one.

- **Rationale:** the content key is byte-identical for every file (it is
  derived from the master key only, with the file id carried as AAD), so a
  per-file copy costs one HKDF + one key schedule but shrinks the key's
  lifetime to the file's.
- **Alternative considered:** keep the shared `ContentEnc` and wipe it on the
  first resource close — rejected, other still-open resources would break.
- **Alternative considered:** derive a per-file key from `masterKey + fileId` —
  rejected, incompatible with the gocryptfs on-disk format.

### 2. The key copy lives on the shared backing file, not each handle

Because handles on one path must share a single `CipherFile` (constraint 1),
the content-key copy is held by that shared `CipherFile`. A handle/stream is
reference-counted onto it (`SharedCipherFile`); the copy is wiped when the last
reference is released and the `CipherFile` is closed.

- **Rationale:** satisfies "wiped when the requiring resource is closed" while
  preserving the file-id coherence the sharing guarantees.
- **Alternative considered:** one `ContentEnc` per handle — rejected, would
  require either duplicating the file-id cache or forking `CipherFile` per
  handle, undoing the existing correctness fix.

### 3. `GocryptFs` becomes a content-key source, not a content-key holder

`GocryptFs` drops its long-lived `contentEnc` field and instead exposes the
derivation (effectively `config.contentEnc(masterKey)`) so `FileManager` and
the transient call sites can mint a fresh `ContentEnc` per use. The EME name
key (`Eme`) stays a `GocryptFs` field and is unchanged.

- **Rationale:** the master key and config are already `GocryptFs` state; the
  derivation method (`ConfigFile.contentEnc`) already exists and wipes the
  intermediate key array.
- **Alternative considered:** a `Supplier<ContentEnc>` cache — rejected, a
  cache would reintroduce a long-lived key-material holder.

### 4. Split keyless block geometry from the keyed cipher

`ContentEnc.cipherSizeToPlainSize`, `plainSizeToCipherSize`,
`blockNoToCipherOff` etc. are pure arithmetic on `plainBS`, `cipherBS`, `ivLen`
and the header length — they need no key. Extract this geometry (a keyless
value, or static helpers) so `DirectoryManager`'s size translation and
`FileManager.plainSizeIncludingWriteBack` do not have to hold key material.

- **Rationale:** metadata/lookup paths should not create or retain a key
  schedule merely to compute sizes.
- **Alternative considered:** mint a throwaway `ContentEnc` for each size
  query — rejected, wasteful and still transiently materialises a key.

### 5. Transient uses mint and wipe a short-lived `ContentEnc`

Symlink-target encryption/decryption (`FileManager.encryptSymlinkTarget` /
`readSymlink`) currently borrow the shared `ContentEnc`. They now mint a
short-lived `ContentEnc`, use it, and wipe it in a `finally` (including the
failure path). Long-name `.name` file access, if it uses the content cipher,
follows the same pattern.

- **Rationale:** these operations are not file/stream/handle resources, but
  they still briefly require key material; the requirement is that no such
  material outlives the operation.

## Risks / Trade-offs

- **Per-open cost.** Each open now pays one HKDF derivation and one AES key
  schedule. → Mitigation: HKDF and key schedule setup are microsecond-scale;
  acceptable against the security benefit, and bulk block I/O still reuses the
  same per-file `ContentEnc`.
- **More `ContentEnc` instances.** Each holds per-thread scratch buffers
  (`TrackedThreadLocal`), so many open files allocate more scratch. → Existing
  `ContentEnc.wipe()` already clears every thread-local; memory is bounded by
  open files, which are already reference-counted and pruned.
- **Wipe ordering on close.** `GocryptFs.close()` must still flush shared files
  before the master key is wiped; per-resource keys must still be alive for
  that flush. → Unchanged ordering: flush, then wipe master; per-resource keys
  are wiped by each `CipherFile.close()` after its final flush.
- **A leaked handle keeps its key copy alive.** If a caller never closes a
  stream/handle, its `CipherFile` (and key copy) stays resident. → Same
  behaviour as today for the shared file; documented caller responsibility.

## Migration Plan

No data migration. The change is internal to the `core` and `nio` modules and
produces byte-identical ciphertext; existing tests (golden files, gocryptfs
interop) must continue to pass unchanged.

## Open Questions

None.
