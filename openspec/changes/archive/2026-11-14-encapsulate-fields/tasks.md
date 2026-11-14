## 1. ContentGeometry encapsulation

- [x] 1.1 Make `ContentGeometry.plainBS/cipherBS/ivLen` private and add `plainBS()`, `cipherBS()`, `ivLen()` accessors
- [x] 1.2 Update `ContentEnc` to read `ContentGeometry` values through the new accessors

## 2. ContentEnc encapsulation

- [x] 2.1 Make `ContentEnc.plainBS/cipherBS/ivLen` private and add `plainBS()`, `cipherBS()`, `ivLen()` accessors
- [x] 2.2 Update `core.CipherFile` to use `ContentEnc` accessors instead of field reads
- [x] 2.3 Update `benchmark.ContentCipherBenchmark` to use `ContentEnc` accessors
- [x] 2.4 Update tests (`CipherFileTest`, `BlockBufferedChannelTest`, `FileManagerTest`, `ContentEncTest`) to use accessors

## 3. PathResolver.Resolved encapsulation

- [x] 3.1 Make `Resolved`'s five fields private and add package-private accessors
- [x] 3.2 Update `FileManager`, `NameManager`, `DirectoryManager` and any other `Resolved` readers to use the accessors

## 4. Tests and verify

- [x] 4.1 Add unit tests covering the new accessors (`plainBS()`, `cipherBS()`, `ivLen()` on `ContentEnc` and `ContentGeometry`, and the `Resolved` accessors)
- [x] 4.2 Compile main and test sources across all modules (`mvn test-compile`)
- [x] 4.3 Run the full test suite (`mvn test`) to confirm no behavior change
