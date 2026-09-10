# gocryptfs4j

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![build](https://github.com/sfuhrm/gocryptfs4j/actions/workflows/build.yml/badge.svg)](https://github.com/sfuhrm/gocryptfs4j/actions/workflows/build.yml)
![Java](https://img.shields.io/badge/Java-11-blue.svg)
[![Coverage](https://raw.githubusercontent.com/sfuhrm/gocryptfs4j/gh-pages/jacoco.svg)]() 
[![ReleaseDate](https://img.shields.io/github/release-date/sfuhrm/gocryptfs4j)](https://github.com/sfuhrm/gocryptfs4j/releases)
[![Maven Central](https://img.shields.io/maven-central/v/de.sfuhrm/gocryptfs4j)](https://central.sonatype.com/artifact/de.sfuhrm/gocryptfs4j)
[![javadoc](https://javadoc.io/badge2/de.sfuhrm/gocryptfs4j/javadoc.svg)](https://javadoc.io/doc/de.sfuhrm/gocryptfs4j)

A pure Java implementation of the [gocryptfs](https://github.com/rfjakob/gocryptfs)
forward-mode on-disk format. It lets Java applications create, read and write
encrypted directories that are fully interchangeable with the original gocryptfs
tool — no FUSE, no native libraries and no gocryptfs binary required.

## What is gocryptfs4j?

gocryptfs4j understands the same ciphertext format as gocryptfs. A directory
encrypted with gocryptfs4j can be mounted and read by the real gocryptfs tool,
and vice versa. It exposes the filesystem through two complementary APIs,
provided by two of the project's [modules](#modules):

* a **plain Java API** (`de.sfuhrm.gocryptfs4j.core.GocryptFs`, in the
  [`core`](#modules) module) for create, open, list, read, write and delete
  operations, and
* a **`java.nio.file.FileSystemProvider`** (`de.sfuhrm.gocryptfs4j.nio.GocryptFsProvider`,
  in the [`nio`](#modules) module) so the filesystem can be used transparently
  through the standard `java.nio.file.Files` / `Path` API.

### Relation to gocryptfs

gocryptfs4j is *not* a wrapper around the gocryptfs binary. It is a clean-room
Java implementation of the [gocryptfs forward-mode on-disk format](https://github.com/rfjakob/gocryptfs/blob/master/Documentation/file-format.md).
Files written by gocryptfs4j use the same layout, encryption and key derivation
as gocryptfs, so both tools operate on the same data:

* **Content encryption:** per 4 KiB block, authenticated with a per-file random
  file ID stored in a header. Three ciphers are supported:
  * AES-256-GCM (the default, matching gocryptfs `-init`),
  * XChaCha20-Poly1305 (gocryptfs `-xchacha`),
  * AES-SIV (RFC 5297, gocryptfs `-aessiv`).
* **Key derivation:** scrypt (RFC 7914) from the password, via Bouncy Castle.
* **Filename encryption:** AES-EME, including gocryptfs long-name handling
  (`> 175` character names) and directory IVs (`gocryptfs.diriv`).
* **Configuration:** the same `gocryptfs.conf` format (JSON), including
  `plaintextnames`, `diriv`/deterministic names, `longnames` and `hkdf` options.

### Features

* Read **and** write gocryptfs forward-mode ciphertext (not read-only).
* Selectable content cipher: AES-256-GCM, XChaCha20-Poly1305 or AES-SIV.
* Random access reads and writes, including partial-block and sparse writes.
* Symlink support.
* Plaintext-names mode for compatibility with setups that disable name encryption.
* No external processes, no JNI, no FUSE — runs anywhere the JVM runs.

## Modules

The project is split into three Maven sub modules. The first two are published
to Maven Central; the third exists only for the build:

| Module     | Directory             | Artifact ID            | Java module                     | Purpose                                                            |
|------------|-----------------------|------------------------|---------------------------------|--------------------------------------------------------------------|
| `core`     | [`core/`](core)       | `gocryptfs4j-core`     | `de.sfuhrm.gocryptfs4j.core`    | The plain Java API (`GocryptFs`) plus the internal crypto, config and name handling. |
| `nio`      | [`nio/`](nio)         | `gocryptfs4j-nio`      | `de.sfuhrm.gocryptfs4j.nio`     | The `java.nio.file` `FileSystemProvider`, built on top of `core`.  |
| `coverage` | [`coverage/`](coverage) | `gocryptfs4j-coverage` | —                               | Build-time only JaCoCo aggregation module; not published.          |

`gocryptfs4j-nio` depends on `gocryptfs4j-core` and re-exports it, so adding
only the `nio` module is enough to use both APIs. The `coverage` module contains
no sources or tests of its own — it merely merges the code-coverage reports of
the other two modules and is skipped for publishing.

## Requirements

* Java 11 or newer (to run).
* JDK 11 or newer (to build).
* Maven 3.x (to build).
* `gocryptfs` and FUSE are **only** needed to run the interop integration tests;
  those tests are skipped automatically when they are absent.

## Building

```bash
mvn clean verify   # build, run unit tests and integration tests
mvn package        # build the jar only (skips integration tests)
```

The build produces the two published artifacts:

* `core/target/gocryptfs4j-core-X.Y.Z.jar` — the plain Java API (the `core` module), and
* `nio/target/gocryptfs4j-nio-X.Y.Z.jar` — the `FileSystemProvider` (the `nio` module).

See [Modules](#modules) for a description of each module.

### Tests

The test suite spans both published modules and is split into unit tests (run by
`mvn test`) and integration tests (run by `mvn verify`).

**Unit tests** — `*Test.java`, in the `core` and `nio` modules:

* Cryptographic known-answer tests against RFC and gocryptfs vectors: scrypt
  (RFC 7914), HKDF (RFC 5869 plus gocryptfs's sub-key vectors), AES-SIV
  (RFC 5297 plus gocryptfs's `TestK64`), AES-GCM (NIST), EME (from
  `rfjakob/eme`) and AES.
* Core API tests for `GocryptFs`, `CipherFile` and `DirEntry`.
* NIO provider tests covering `Files` traversal/read/write, `PathMatcher`
  (glob/regex), `WatchService` and `UserPrincipalLookupService`.
* Golden fixtures from the reference gocryptfs, committed under
  `core/src/test/resources/`, verify that gocryptfs4j decrypts real
  gocryptfs-produced ciphertext: legacy v0.11 `gocryptfs.conf` files and the
  v1.3 example filesystem (HKDF, EME names, GCM content, long names, symlinks).

**Integration tests** — `*IT.java`, skipped automatically when `gocryptfs` is
not on `PATH`:

* `GocryptfsInteropIT` — small bidirectional round-trip (gocryptfs writes →
  gocryptfs4j reads and vice versa) across all ciphers and name modes.
* `LinuxKernelInteropIT` / `LinuxKernelNioInteropIT` — download the Linux kernel
  1.0 source tree and verify it round-trips byte-for-byte (including sizes and
  timestamps) against the real `gocryptfs` binary, via the plain API and the NIO
  view respectively. Requires FUSE.
* `GocryptfsToolingIT` — uses `gocryptfs -info`, `-fsck` and `-passwd` as an
  oracle against gocryptfs4j-written directories. `-info` and `-passwd` need
  only the binary; `-fsck` additionally needs FUSE.

## Usage

### 1. Plain Java API (`core` module)

```java
import de.sfuhrm.gocryptfs4j.core.DirEntry;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

// Create a new encrypted filesystem. The directory must exist and be empty.
Path cipherDir = Path.of("/data/cipher");
try (GocryptFs fs = GocryptFs.create(cipherDir, "my-password".toCharArray())) {
    fs.mkdir("/docs");
    fs.createFile("/docs/hello.txt");
    fs.write("/docs/hello.txt", 0, "hello gocryptfs".getBytes(StandardCharsets.UTF_8));
}

// Later, open it again and read back.
try (GocryptFs fs = GocryptFs.open(cipherDir, "my-password".toCharArray())) {
    for (DirEntry e : fs.list("/")) {
        System.out.println(e.plainName() + " (" + e.kind() + ", " + e.size() + " bytes)");
    }
    String content = new String(fs.readAll("/docs/hello.txt"), StandardCharsets.UTF_8);
}
```

The `GocryptFs` object is `AutoCloseable` and wipes the master key from memory
on `close()`. Other operations include `size`, `truncate`, `delete`,
`createSymlink`, `readSymlinkTarget`, `setTimes` and `openRead` (a streaming
decrypting `InputStream`).

### 2. NIO `FileSystemProvider` (`nio` module)

The provider is registered as a service, so it can be obtained via
`FileSystems.newFileSystem` and used with the standard `Files` API:

```java
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

Map<String, Object> env = new HashMap<>();
env.put("cipherDir", Path.of("/data/cipher"));   // Path or String
env.put("password", "my-password".toCharArray()); // char[]

try (FileSystem fs = FileSystems.newFileSystem(URI.create("gocryptfs:///"), env)) {
    Path root = fs.getPath("/");

    Files.createDirectory(root.resolve("docs"));
    Files.writeString(root.resolve("docs/hello.txt"), "hello gocryptfs");

    String content = Files.readString(root.resolve("docs/hello.txt"));
}
```

Alternatively, instantiate the provider directly:

```java
import de.sfuhrm.gocryptfs4j.nio.GocryptFsProvider;

try (FileSystem fs = new GocryptFsProvider()
        .newFileSystem(Path.of("/data/cipher"), "my-password".toCharArray())) {
    // ... use java.nio.file.Files on fs.getPath("/") as above
}
```

> Note: the NIO view currently exposes basic attributes (type, size, times).
> POSIX permissions and ownership are not yet mapped.

### 3. Options: content cipher and plaintext names

The content cipher and name-encryption mode are chosen at creation time via the
`ContentCipherType` enum (`de.sfuhrm.gocryptfs4j.core.ContentCipherType`):

```java
import de.sfuhrm.gocryptfs4j.core.ContentCipherType;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;

// AES-256-GCM (default), XChaCha20-Poly1305 or AES-SIV:
try (GocryptFs fs = GocryptFs.create(
        cipherDir, "pw".toCharArray(), false, ContentCipherType.AES_SIV)) {
    // ...
}
```

| `ContentCipherType`      | gocryptfs flag    | Description                                   |
|--------------------------|-------------------|-----------------------------------------------|
| `AES_GCM`                | (default)         | AES-256-GCM, 128-bit IVs                      |
| `XCHACHA20_POLY1305`     | `-xchacha`        | XChaCha20-Poly1305, 24-byte nonces            |
| `AES_SIV`                | `-aessiv`         | AES-SIV (RFC 5297), nonce-misuse resistant    |

The third `create` argument controls plaintext (unencrypted) names: pass
`true` to disable filename encryption (gocryptfs `-plaintextnames`), or `false`
for the default EME-encrypted names. Filesystems are always opened
automatically with the correct cipher, since it is stored in `gocryptfs.conf`.

## Maven coordinates

The `core` module (the plain Java API):

```xml
<dependency>
    <groupId>de.sfuhrm</groupId>
    <artifactId>gocryptfs4j-core</artifactId>
    <version>0.2.0</version>
</dependency>
```

The `nio` module (the `FileSystemProvider`) is a separate artifact that depends
on, and re-exports, the `core` module:

```xml
<dependency>
    <groupId>de.sfuhrm</groupId>
    <artifactId>gocryptfs4j-nio</artifactId>
    <version>0.2.0</version>
</dependency>
```

> Note: the `coverage` module is not published and has no Maven coordinates.

## License

[MIT](https://opensource.org/licenses/MIT)
