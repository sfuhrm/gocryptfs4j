# gocryptfs4j tutorial

This tutorial walks through the lifecycle of a gocryptfs4j filesystem for each
of the three approaches. Every filesystem goes through the same four phases:

1. **init** — create a new encrypted filesystem or open an existing one,
2. **directory listing** — list the plaintext view of a directory,
3. **access** — read and write file content,
4. **deinit** — close the filesystem, which wipes the key material.

All snippets assume the cipher directory exists and (for `create`) is empty.

- [1. Plain Java API (`core` module)](#1-plain-java-api-core-module)
- [2. NIO `FileSystemProvider` (`nio` module)](#2-nio-filesystemprovider-nio-module)
- [3. FIDO2-protected filesystems (`libfido2` module)](#3-fido2-protected-filesystems-libfido2-module)

---

## 1. Plain Java API (`core` module)

The plain API is centered on
[`GocryptFs`](../core/src/main/java/de/sfuhrm/gocryptfs4j/core/GocryptFs.java),
which performs all name and content encryption on top of a
[`CipherStore`](../core/src/main/java/de/sfuhrm/gocryptfs4j/store/CipherStore.java).
Use `PathCipherStore` for the local filesystem, or supply your own store for a
remote backend.

### init

Create a new filesystem (the directory must exist and be empty):

```java
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

Path cipherDir = Paths.get("/data/cipher");
Files.createDirectories(cipherDir);            // must exist and be empty

CipherStore store = new PathCipherStore(cipherDir);
GocryptFs fs = GocryptFs.create(store, "my-password".toCharArray());
```

Open an existing filesystem later:

```java
CipherStore store = new PathCipherStore(Paths.get("/data/cipher"));
GocryptFs fs = GocryptFs.open(store, "my-password".toCharArray());
```

The password is used to unlock the master key via scrypt; it is never retained.

### directory listing

`list` returns the plaintext view of a directory as
[`DirEntry`](../core/src/main/java/de/sfuhrm/gocryptfs4j/core/DirEntry.java)
objects:

```java
for (DirEntry e : fs.list("/")) {
    System.out.println(e.plainName() + " (" + e.kind() + ", " + e.size() + " bytes)");
}
```

`DirEntry` exposes the plaintext name, the entry kind (`FILE`, `DIRECTORY`,
`SYMLINK` or `OTHER`), the plaintext size, and the timestamps. `stat` returns the
same information for a single path.

### access

Read a whole file into memory:

```java
byte[] content = fs.readAll("/docs/hello.txt");
```

Read as a streaming, decrypting `InputStream`:

```java
try (InputStream in = fs.openRead("/docs/hello.txt")) {
    // consume the plaintext stream
}
```

Write bytes at a plaintext offset (random access, partial-block and sparse
writes are supported):

```java
fs.createFile("/docs/hello.txt");
fs.write("/docs/hello.txt", 0, "hello gocryptfs".getBytes(StandardCharsets.UTF_8));
```

Write as a streaming, encrypting `OutputStream` (truncates the file first):

```java
try (OutputStream out = fs.openWrite("/docs/hello.txt")) {
    out.write("hello gocryptfs".getBytes(StandardCharsets.UTF_8));
}
```

Other operations include `mkdir`, `delete`, `rename`, `createSymlink`,
`readSymlinkTarget`, `size`, `truncate` and `setTimes`.

### deinit

`GocryptFs` is `AutoCloseable`. Closing it wipes the master key and every
derived key from memory — use try-with-resources so this always happens:

```java
try (GocryptFs fs = GocryptFs.open(store, "my-password".toCharArray())) {
    // ... init, listing, access ...
}
// the master key and all derived keys have been wiped here
```

---

## 2. NIO `FileSystemProvider` (`nio` module)

The `nio` module exposes the plaintext view through the standard
`java.nio.file.Files` / `Path` API, so existing code can work with an encrypted
directory transparently.

### init

The provider is registered as a service, so it can be obtained via
`FileSystems.newFileSystem`:

```java
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

Map<String, Object> env = new HashMap<>();
env.put("cipherDir", Paths.get("/data/cipher"));   // Path or String
env.put("password", "my-password".toCharArray());

FileSystem fs = FileSystems.newFileSystem(URI.create("gocryptfs:///"), env);
Path root = fs.getPath("/");
```

Alternatively, instantiate the provider directly:

```java
import de.sfuhrm.gocryptfs4j.nio.GocryptFsProvider;

FileSystem fs = new GocryptFsProvider()
        .newFileSystem(Paths.get("/data/cipher"), "my-password".toCharArray());
Path root = fs.getPath("/");
```

Note: `newFileSystem` *opens* an existing filesystem. To create one, use the
plain API's `GocryptFs.create(...)` once first, then open it through NIO.

### directory listing

Use the standard `Files` API:

```java
try (DirectoryStream<Path> stream = Files.newDirectoryStream(root)) {
    for (Path path : stream) {
        System.out.println(path.getFileName());
    }
}
```

### access

Read and write with `Files`:

```java
Files.createDirectory(root.resolve("docs"));
Files.write(root.resolve("docs/hello.txt"),
        "hello gocryptfs".getBytes(StandardCharsets.UTF_8));

byte[] content = Files.readAllBytes(root.resolve("docs/hello.txt"));
```

The `PathMatcher`, `WatchService`, `UserPrincipalLookupService` and POSIX
attribute views are also supported where the backing filesystem allows them.

### deinit

`FileSystem` is `AutoCloseable`; closing it closes the underlying `GocryptFs`
and wipes its keys:

```java
try (FileSystem fs = FileSystems.newFileSystem(URI.create("gocryptfs:///"), env)) {
    // ... init, listing, access ...
}
```

---

## 3. FIDO2-protected filesystems (`libfido2` module)

FIDO2 support replaces the password with a security key's `hmac-secret`. Create
and open take a `Fido2Token` (here the libfido2-backed `LibFido2Token`) instead
of a password.

### init

Create a new filesystem (registers a credential on the key):

```java
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
import de.sfuhrm.gocryptfs4j.fido2.libfido2.LibFido2Token;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.local.PathCipherStore;

Fido2Token token = new LibFido2Token("/dev/hidraw5");   // list with: fido2-token -L
CipherStore store = new PathCipherStore(Paths.get("/data/cipher"));

GocryptFs fs = GocryptFs.create(store, token);
```

Open an existing filesystem (reads the credential ID and salt from
`gocryptfs.conf` and asks the token for the secret):

```java
GocryptFs fs = GocryptFs.open(store, token);
```

### directory listing

Identical to the plain API:

```java
for (DirEntry e : fs.list("/")) {
    System.out.println(e.plainName());
}
```

### access

Identical to the plain API:

```java
fs.write("/hello.txt", 0, "hello fido2".getBytes(StandardCharsets.UTF_8));
byte[] content = fs.readAll("/hello.txt");
```

### deinit

Identical to the plain API — `GocryptFs` is `AutoCloseable`, and closing wipes
the master key, the derived keys and the token secret:

```java
try (GocryptFs fs = GocryptFs.open(store, token)) {
    // ... init, listing, access ...
}
```
