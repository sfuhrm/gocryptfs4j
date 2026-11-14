## 1. Extract keyless block geometry

- [x] 1.1 Introduce a keyless content geometry value/helper carrying `plainBS`, `cipherBS` and `ivLen` (and the existing offset/size translation methods), so size translation and block-offset math need no key material
- [x] 1.2 Point `DirectoryManager` size translation and `FileManager.plainSizeIncludingWriteBack` at the keyless geometry instead of a keyed `ContentEnc`

## 2. Make `GocryptFs` a content-key source

- [x] 2.1 Remove the long-lived `contentEnc` field from `GocryptFs` and add a per-use derivation entry point that calls `ConfigFile.contentEnc(masterKey)` on demand
- [x] 2.2 Keep the EME name key (`Eme`) and the master key owned and wiped by `GocryptFs.close()` as today

## 3. Per-resource content key in `CipherFile`

- [x] 3.1 Change `CipherFile.open` to take a freshly derived `ContentEnc` (built per file) instead of a shared one
- [x] 3.2 Wipe the file's own `ContentEnc` in `CipherFile.close()` (in addition to the existing scratch-buffer wipe)
- [x] 3.3 Ensure the shared `SharedCipherFile.Entry` builds/derives a fresh `ContentEnc` when it creates its backing `CipherFile`, and wipes it via `CipherFile.close()` on last-release

## 4. Transient content-key uses

- [x] 4.1 Update `FileManager.encryptSymlinkTarget` / `readSymlink` (and `DirectoryManager`'s listing path) to mint a short-lived `ContentEnc`, use it, and wipe it in a `finally` including the failure path
- [x] 4.2 Audit long-name `.name` file access in `DirectoryManager`/`NameManager` and apply the same short-lived pattern wherever the content cipher is used

## 5. Verify and document

- [x] 5.1 Run the existing test suite (golden files, gocryptfs interop, FIDO2, NIO) to confirm byte-identical ciphertext and no regressions
- [x] 5.2 Add/adjust tests asserting that closing a file/stream/handle wipes its content-key material and that remaining open resources stay usable
- [x] 5.3 Update javadoc on `GocryptFs`, `CipherFile` and `SharedCipherFile` to describe the per-resource key-material lifetime
