## Context

The codebase already keeps fields `private` and exposes state through methods
almost everywhere (`DirEntry.kind()`, `size()`, `ConfigFile` accessors, etc.).
Three types are the exception, exposing `public final` instance fields:

- `ContentEnc.plainBS` / `cipherBS` / `ivLen` — read by `CipherFile` (core) and
  `ContentCipherBenchmark`, and by tests.
- `ContentGeometry.plainBS` / `cipherBS` / `ivLen` — read by `ContentEnc`
  (same package) only.
- `PathResolver.Resolved.cipherPath` / `cipherParent` / `parentDirIV` /
  `cipherName` / `plainName` — read across the `core` package.

See proposal.md for motivation. `public static final` constants are out of scope.

## Goals / Non-Goals

**Goals:**
- Make every non-constant instance field `private`.
- Provide accessor methods only where a value is needed outside its package.
- Preserve behavior, byte output, and the existing public method API (except the
  removed field reads).

**Non-Goals:**
- Touching `public static final` constants.
- Restructuring value objects into new abstractions; the change is mechanical
  encapsulation, not a redesign.
- Adding setters: these types are immutable value holders, so only read
  accessors apply.

## Decisions

### 1. `ContentEnc` fields become `private` with public getters

`plainBS`, `cipherBS` and `ivLen` become `private final`, and public methods
`plainBS()`, `cipherBS()`, `ivLen()` are added.

- **Rationale:** `CipherFile` (different package) and the benchmark genuinely
  need block sizes and nonce length, so accessors are warranted. This is a
  **BREAKING** change for clients that read the fields directly; they migrate to
  the same-named methods.
- **Alternative considered:** keep fields package-private and have `CipherFile`
  use a new accessor on `ContentGeometry` — rejected, it would still expose
  state indirectly and complicate `CipherFile`/benchmark code.

### 2. `ContentGeometry` fields become `private` with public getters

Same treatment: `private final` fields plus `plainBS()`, `cipherBS()`,
`ivLen()`.

- **Rationale:** `ContentGeometry` is a public value type returned by
  `ConfigFile.contentGeometry()` and `ContentEnc.geometry()`; its dimensions are
  its whole purpose, and `ContentEnc` itself needs them. Public getters keep the
  type consistent with `ContentEnc`.
- **Alternative considered:** package-private getters only — rejected, the type
  is already public API and the values are the point of the type.

### 3. `PathResolver.Resolved` fields become `private` with package-private getters

The five fields become `private final`, with package-private (default-access)
getter methods, and all readers in the `core` package switch to them.

- **Rationale:** `Resolved` is package-private (not public API), so its
  accessors must not widen visibility. Getter methods preserve the value-object
  shape while satisfying the encapsulation rule.
- **Alternative considered:** leave the fields package-private (drop only
  `public`) — rejected, the rule requires `private`.

### 4. Update all readers mechanically

`CipherFile`, `ContentCipherBenchmark`, the tests (`CipherFileTest`,
`BlockBufferedChannelTest`, `FileManagerTest`, `ContentEncTest`), and every
`Resolved` consumer in `FileManager` / `NameManager` / `DirectoryManager` switch
from field reads to accessor calls.

- **Rationale:** no behavior change; purely rename `x.f` to `x.f()`.

## Risks / Trade-offs

- **Source-compatibility break for `ContentEnc`/`ContentGeometry` field
  readers.** → Documented as BREAKING; migration is a mechanical rename to the
  accessor of the same name.
- **Churn in `core` internals from the `Resolved` change.** → Mechanical and
  covered by the existing test suite; behavior is unchanged.
- **Missed readers causing a compile break.** → The full `mvn test` build
  (main + test compile across modules) catches every reader.

## Migration Plan

No data or on-disk migration. This is a source-level API change; consumers using
`ContentEnc`/`ContentGeometry` field reads update to the same-named methods.
The library's own modules and tests are updated in the same change.

## Open Questions

None.
