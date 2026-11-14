## Why

A few value types expose internal state as `public final` fields
(`ContentEnc.plainBS/cipherBS/ivLen`, `ContentGeometry.plainBS/cipherBS/ivLen`,
and `PathResolver.Resolved.*`), while the rest of the library already keeps
fields `private` and exposes state only through accessors. Direct field access
freezes the representation and bypasses the tell-don't-ask style used elsewhere.

## What Changes

- Make every non-constant instance field `private`.
- Add accessors only where a value is genuinely needed outside its package; no
  accessor is added for internal-only state.
- **BREAKING**: `ContentEnc.plainBS`, `cipherBS` and `ivLen` become methods
  `plainBS()`, `cipherBS()`, `ivLen()`.
- **BREAKING**: `ContentGeometry.plainBS`, `cipherBS` and `ivLen` become
  methods of the same names.
- `PathResolver.Resolved` fields become `private`, read through package-private
  accessors.

## Out of Scope

- `public static final` constants (protocol sizes, key lengths, feature-flag
  names) remain public and unchanged.
- No restructuring of value objects, no setters (the types are immutable value
  holders), no behavior or byte-output change.

## Capabilities

### New Capabilities
- `api-encapsulation`: field visibility and state access across the library —
  fields are private, state is exposed only via accessors when a client needs
  it, and objects act on their own state (tell-don't-ask).

### Modified Capabilities
<!-- none -->

## Impact

- `core` module: `crypto.ContentEnc`, `crypto.ContentGeometry`,
  `core.PathResolver.Resolved`, and their readers (`core.CipherFile`,
  `benchmark.ContentCipherBenchmark`, tests).
- Source-level API change on `ContentEnc`/`ContentGeometry` (field reads become
  method calls); consumers must migrate. No on-disk or byte-compatibility
  change.
