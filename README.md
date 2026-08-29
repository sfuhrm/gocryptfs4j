# gocryptfs4j

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![build](https://github.com/sfuhrm/gocryptfs4j/actions/workflows/build.yml/badge.svg)](https://github.com/sfuhrm/gocryptfs4j/actions/workflows/build.yml)

A pure Java implementation of the [gocryptfs](https://github.com/rfjakob/gocryptfs)
forward-mode on-disk format. It lets Java applications create, read and write
encrypted directories that are fully interchangeable with the original gocryptfs
tool — no FUSE, no native libraries and no gocryptfs binary required.

## What is gocryptfs4j?

gocryptfs4j understands the same ciphertext format as gocryptfs. A directory
encrypted with gocryptfs4j can be mounted and read by the real gocryptfs tool,
and vice versa. It exposes the filesystem through two complementary APIs:

* a **plain Java API** (`de.sfuhrm.gocryptfs4j.fs.GocryptFs`) for create,
  open, list, read, write and delete operations, and
* a **`java.nio.file.FileSystemProvider`** (`de.sfuhrm.gocryptfs4j.nio.GocryptFsProvider`)
  so the filesystem can be used transparently through the standard
  `java.nio.file.Files` / `Path` API.

### Relation to gocryptfs

gocryptfs4j is *not* a wrapper around the gocryptfs binary. It is a clean-room
Java implementation of the [gocryptfs forward-mode on-disk format](https://github.com/rfjakob/gocryptfs/blob/master/Documentation/file-format.md).
Files written by gocryptfs4j use the same layout, encryption and key derivation
as gocryptfs, so both tools operate on the same data:

* **Content encryption:** AES-256-GCM per 4 KiB block, authenticated with a
  per-file random file ID stored in a header.
* **Key derivation:** scrypt (RFC 7914) from the password, via Bouncy Castle.
* **Filename encryption:** AES-EME, including gocryptfs long-name handling
  (`> 175` character names) and directory IVs (`gocryptfs.diriv`).
* **Configuration:** the same `gocryptfs.conf` format (JSON), including
  `plaintextnames`, `diriv`/deterministic names, `longnames` and `hkdf` options.

### Features

* Read **and** write gocryptfs forward-mode ciphertext (not read-only).
* Random access reads and writes, including partial-block and sparse writes.
* Symlink support.
* Plaintext-names mode for compatibility with setups that disable name encryption.
* No external processes, no JNI, no FUSE — runs anywhere the JVM runs.

## Requirements

* Java 17 or newer.
* Maven 3.x (to build).
* `gocryptfs` and FUSE are **only** needed to run the interop integration tests;
  those tests are skipped automatically when they are absent.

## Building

```bash
mvn clean verify   # build, run unit tests and integration tests
mvn package        # build the jar only (skips integration tests)
```

The build produces `target/gocryptfs4j-0.1.0.jar`.

### Tests

* Unit tests exercise key derivation, EME, content encryption and the API.
* Integration tests (`*IT.java`) download the Linux kernel 1.0 source tree and
  verify it round-trips byte-for-byte (including sizes and timestamps) against
  the real `gocryptfs` binary, in both directions. They are picked up by
  `mvn verify` and skip gracefully when `gocryptfs` or FUSE are unavailable.

## Usage

### 1. Plain Java API

```java
import de.sfuhrm.gocryptfs4j.fs.DirEntry;
import de.sfuhrm.gocryptfs4j.fs.GocryptFs;

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

### 2. NIO `FileSystemProvider`

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
env.put("password", "my-password".toCharArray()); // String or char[]

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

## Maven coordinates

```xml
<dependency>
    <groupId>de.sfuhrm</groupId>
    <artifactId>gocryptfs4j</artifactId>
    <version>0.1.0</version>
</dependency>
```

## License

[MIT](https://opensource.org/licenses/MIT)
