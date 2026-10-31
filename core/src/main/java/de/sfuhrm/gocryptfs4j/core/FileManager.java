package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Performs plaintext file operations (read, write, attributes, create, delete,
 * rename) and symlink operations on top of the ciphertext store.
 *
 * <p>Every operation takes a plaintext path, resolves it to a ciphertext path
 * via the {@link PathResolver}, and performs the underlying store operation
 * plus any encryption and long-name bookkeeping. Symlink targets are encrypted
 * with the content cipher and base64url-encoded, as in gocryptfs.</p>
 */
final class FileManager {

    /** The ciphertext-side store. */
    private final CipherStore store;

    /** The content-encryption helper. */
    private final ContentEnc contentEnc;

    /** The name-transform helper. */
    private final NameTransform nameTransform;

    /** Whether file names are stored unencrypted. */
    private final boolean plaintextNames;

    /** The name manager. */
    private final NameManager nameManager;

    /** The directory manager. */
    private final DirectoryManager directoryManager;

    /** The path resolver. */
    private final PathResolver pathResolver;

    /**
     * Creates a file manager.
     *
     * @param store            the ciphertext-side store
     * @param contentEnc       the content-encryption helper
     * @param nameTransform    the name-transform helper
     * @param plaintextNames   whether file names are stored unencrypted
     * @param nameManager      the name manager
     * @param directoryManager the directory manager
     * @param pathResolver     the path resolver
     * @throws NullPointerException if a required argument is {@code null}
     */
    FileManager(CipherStore store, ContentEnc contentEnc, NameTransform nameTransform,
                boolean plaintextNames, NameManager nameManager,
                DirectoryManager directoryManager, PathResolver pathResolver) {
        this.store = Objects.requireNonNull(store, "store");
        this.contentEnc = Objects.requireNonNull(contentEnc, "contentEnc");
        this.nameTransform = Objects.requireNonNull(nameTransform, "nameTransform");
        this.plaintextNames = plaintextNames;
        this.nameManager = Objects.requireNonNull(nameManager, "nameManager");
        this.directoryManager = Objects.requireNonNull(directoryManager, "directoryManager");
        this.pathResolver = Objects.requireNonNull(pathResolver, "pathResolver");
    }

    // ------------------------------------------------------------------
    // Attributes
    // ------------------------------------------------------------------

    /**
     * Returns the plaintext attributes of a path (file, directory or symlink).
     *
     * @param plainPath the plaintext path
     * @return the directory entry
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    DirEntry stat(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        return statResolved(r);
    }

    /**
     * Reads the attributes of an already-resolved path.
     *
     * @param r the resolved path
     * @return the directory entry
     * @throws IOException on filesystem errors
     */
    private DirEntry statResolved(PathResolver.Resolved r) throws IOException {
        CipherNode node = store.stat(r.cipherPath);
        DirEntry.Kind kind;
        long size;
        if (node.isDirectory()) {
            kind = DirEntry.Kind.DIRECTORY;
            size = 0;
        } else if (node.isSymbolicLink()) {
            kind = DirEntry.Kind.SYMLINK;
            size = readSymlink(r.cipherPath).getBytes(StandardCharsets.UTF_8).length;
        } else if (node.isRegularFile()) {
            kind = DirEntry.Kind.FILE;
            size = contentEnc.cipherSizeToPlainSize(node.size());
        } else {
            kind = DirEntry.Kind.OTHER;
            size = node.size();
        }
        String plainName = r.plainName.isEmpty() ? "/" : r.plainName;
        return new DirEntry(plainName, r.cipherName, store.posixAttributes(r.cipherPath), kind, size,
                node.lastModifiedTime(), node.lastAccessTime(), node.creationTime(),
                node.fileKey());
    }

    // ------------------------------------------------------------------
    // Content access
    // ------------------------------------------------------------------

    /**
     * Opens a plaintext file for random access.
     *
     * @param plainFile the plaintext file path
     * @param writable  whether to open for writing
     * @return the opened cipher file
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    CipherFile openCipherFile(String plainFile, boolean writable) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        return openCipherFileByName(r.cipherPath, writable);
    }

    /**
     * Opens a cipher-side file for random access.
     *
     * @param cipherFile the ciphertext file name
     * @param writable   whether to open for writing
     * @return the opened cipher file
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherFile} is {@code null}
     */
    CipherFile openCipherFileByName(String cipherFile, boolean writable) throws IOException {
        Objects.requireNonNull(cipherFile, "cipherFile");
        CipherChannel channel = store.open(cipherFile, writable);
        return CipherFile.open(channel, contentEnc, writable);
    }

    /**
     * Returns the plaintext size of a file.
     *
     * @param plainFile the plaintext file path
     * @return the plaintext size in bytes
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    long size(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        try (CipherFile cf = openCipherFileByName(r.cipherPath, false)) {
            return cf.plainSize();
        }
    }

    /**
     * Reads the entire plaintext content of a file.
     *
     * @param plainFile the plaintext file path
     * @return the plaintext content
     * @throws IOException on filesystem or decryption errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    byte[] readAll(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        try (CipherFile cf = openCipherFileByName(r.cipherPath, false)) {
            long size = cf.plainSize();
            if (size > Integer.MAX_VALUE) {
                throw new IOException("file too large to read into memory: " + size);
            }
            byte[] out = new byte[(int) size];
            int pos = 0;
            while (pos < size) {
                int n = cf.read(ByteBuffer.wrap(out, pos, (int) (size - pos)), pos);
                if (n < 0) {
                    break;
                }
                pos += n;
            }
            return Arrays.copyOf(out, pos);
        }
    }

    /**
     * Opens a streaming, decrypting input stream over a plaintext file path.
     *
     * @param plainFile the plaintext file path
     * @return the decrypting input stream
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    InputStream openRead(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        CipherFile cf = openCipherFileByName(r.cipherPath, false);
        try {
            return new CipherInputStream(cf);
        } catch (RuntimeException e) {
            cf.close();
            throw e;
        }
    }

    /**
     * Opens a streaming, encrypting output stream over a plaintext file path.
     *
     * <p>Writing starts at the beginning of the file, overwriting any existing
     * content. Closing the stream closes the underlying file and flushes the
     * encrypted data.</p>
     *
     * @param plainFile the plaintext file path
     * @return the encrypting output stream
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    OutputStream openWrite(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        CipherFile cf = openCipherFileByName(r.cipherPath, true);
        try {
            cf.truncate(0);
            return Channels.newOutputStream(cf.writeChannel(0));
        } catch (IOException | RuntimeException e) {
            cf.close();
            throw e;
        }
    }

    /**
     * Writes {@code data} at plaintext {@code offset} of an existing file.
     *
     * @param plainFile the plaintext file path
     * @param offset    the plaintext offset to write at
     * @param data      the data to write
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plainFile} or {@code data} is {@code null}
     * @throws IllegalArgumentException if {@code offset} is negative
     */
    void write(String plainFile, long offset, byte[] data) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        Objects.requireNonNull(data, "data");
        if (offset < 0) {
            throw new IllegalArgumentException("negative offset: " + offset);
        }
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        try (CipherFile cf = openCipherFileByName(r.cipherPath, true)) {
            ByteBuffer buf = ByteBuffer.wrap(data);
            long pos = offset;
            while (buf.hasRemaining()) {
                int n = cf.write(buf, pos);
                if (n <= 0) {
                    throw new IOException("no progress writing to " + plainFile);
                }
                pos += n;
            }
        }
    }

    /**
     * Truncates a plaintext file to {@code newSize} bytes.
     *
     * @param plainFile the plaintext file path
     * @param newSize   the new plaintext size in bytes
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     * @throws IllegalArgumentException if {@code newSize} is negative
     */
    void truncate(String plainFile, long newSize) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        if (newSize < 0) {
            throw new IllegalArgumentException("negative size: " + newSize);
        }
        PathResolver.Resolved r = pathResolver.resolve(plainFile);
        try (CipherFile cf = openCipherFileByName(r.cipherPath, true)) {
            cf.truncate(newSize);
        }
    }

    // ------------------------------------------------------------------
    // Metadata
    // ------------------------------------------------------------------

    /**
     * Sets the last-modified, last-access and creation times of a path.
     *
     * @param plainPath        the plaintext path
     * @param lastModifiedTime the last-modified time
     * @param lastAccessTime   the last-access time
     * @param createTime       the creation time
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    void setTimes(String plainPath, @Nullable FileTime lastModifiedTime,
                  @Nullable FileTime lastAccessTime, @Nullable FileTime createTime)
            throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.setTimes(r.cipherPath, lastModifiedTime, lastAccessTime, createTime);
    }

    /**
     * Checks access to a plaintext path, delegating to the store. Existence (no
     * modes) is verified by resolving the path itself; stores that cannot
     * evaluate read/write/execute throw {@link UnsupportedOperationException}.
     *
     * @param plainPath the plaintext path
     * @param modes     the access modes to check, or none to check existence
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    void checkAccess(String plainPath, AccessMode... modes) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.checkAccess(r.cipherPath, modes);
    }

    /**
     * Returns the POSIX attributes of a plaintext path's backing cipher file,
     * or {@code null} if the store has no POSIX support.
     *
     * @param plainPath the plaintext path
     * @return the POSIX attributes, or {@code null}
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    @Nullable PosixFileAttributes posixAttributes(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        return store.posixAttributes(r.cipherPath);
    }

    /**
     * Sets the POSIX permissions of a plaintext path's backing cipher file.
     *
     * @param plainPath   the plaintext path
     * @param permissions the new permissions
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} or {@code permissions} is {@code null}
     */
    void setPosixPermissions(String plainPath, Set<PosixFilePermission> permissions)
            throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(permissions, "permissions");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.setPosixPermissions(r.cipherPath, permissions);
    }

    /**
     * Sets the POSIX owner of a plaintext path's backing cipher file.
     *
     * @param plainPath the plaintext path
     * @param owner     the new owner
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} or {@code owner} is {@code null}
     */
    void setPosixOwner(String plainPath, UserPrincipal owner) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(owner, "owner");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.setPosixOwner(r.cipherPath, owner);
    }

    /**
     * Sets the POSIX group of a plaintext path's backing cipher file.
     *
     * @param plainPath the plaintext path
     * @param group     the new group
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} or {@code group} is {@code null}
     */
    void setPosixGroup(String plainPath, GroupPrincipal group) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(group, "group");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        store.setPosixGroup(r.cipherPath, group);
    }

    // ------------------------------------------------------------------
    // Create / delete / rename
    // ------------------------------------------------------------------

    /**
     * Creates an empty file (fails if it already exists).
     *
     * @param plainFile the plaintext file path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainFile} is {@code null}
     */
    void createFile(String plainFile) throws IOException {
        Objects.requireNonNull(plainFile, "plainFile");
        PathResolver.Resolved r = pathResolver.resolveParent(plainFile);
        boolean wroteName = nameManager.prepareLongName(r);
        try {
            store.createFile(r.cipherPath);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                nameManager.removeLongName(r);
            }
            throw e;
        }
    }

    /**
     * Creates a directory (including its diriv).
     *
     * @param plainDir the plaintext directory path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainDir} is {@code null}
     */
    void mkdir(String plainDir) throws IOException {
        Objects.requireNonNull(plainDir, "plainDir");
        PathResolver.Resolved r = pathResolver.resolveParent(plainDir);
        boolean wroteName = nameManager.prepareLongName(r);
        try {
            store.mkdir(r.cipherPath);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                nameManager.removeLongName(r);
            }
            throw e;
        }
        try {
            directoryManager.writeDirIV(r.cipherPath);
        } catch (IOException | RuntimeException e) {
            try {
                deleteIfExists(store, PathResolver.join(r.cipherPath, Constants.DIR_IV_FILENAME));
                store.delete(r.cipherPath);
                nameManager.removeLongName(r);
            } catch (IOException cleanup) {
                e.addSuppressed(cleanup);
            }
            throw e;
        }
    }

    /**
     * Deletes a file, symlink or empty directory.
     *
     * @param plainPath the plaintext path
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    void delete(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        if (store.stat(r.cipherPath).isDirectory()) {
            // Verify the directory is empty apart from its gocryptfs.diriv
            // before removing anything, so that rejecting a non-empty delete
            // leaves the directory (and its diriv) intact.
            for (CipherNode entry : store.list(r.cipherPath)) {
                if (!entry.name().equals(Constants.DIR_IV_FILENAME)) {
                    throw new DirectoryNotEmptyException(r.cipherPath);
                }
            }
            deleteIfExists(store, PathResolver.join(r.cipherPath, Constants.DIR_IV_FILENAME));
            store.delete(r.cipherPath);
        } else {
            store.delete(r.cipherPath);
        }
        nameManager.removeLongName(r);
        directoryManager.invalidateDirIvCache(r.cipherPath);
    }

    /**
     * Renames (moves) a file, symlink or directory within this filesystem by
     * renaming the single ciphertext entry.
     *
     * <p>No content is read or re-encrypted: file content is bound to the file
     * ID stored in its header, directory contents are bound to the directory's
     * own {@code gocryptfs.diriv}, and symlink targets are not path-bound, so
     * only the entry's encrypted name (and its long-name support file, if any)
     * changes. Directories are therefore moved together with their whole
     * subtree. An existing file or symlink target is replaced atomically;
     * only a directory target is removed first, after verifying it is empty
     * apart from its {@code gocryptfs.diriv}.</p>
     *
     * @param plainFrom       the plaintext source path
     * @param plainTo         the plaintext target path
     * @param replaceExisting whether an existing target (a file, symlink or
     *                        empty directory) may be replaced
     * @throws NoSuchFileException if the source or the target's parent does not exist
     * @throws FileAlreadyExistsException if the target exists and {@code replaceExisting} is {@code false}
     * @throws DirectoryNotEmptyException if the target is a non-empty directory
     * @throws IOException if the target lies inside the source or on filesystem errors
     * @throws NullPointerException if an argument is {@code null}
     */
    void rename(String plainFrom, String plainTo, boolean replaceExisting)
            throws IOException {
        Objects.requireNonNull(plainFrom, "plainFrom");
        Objects.requireNonNull(plainTo, "plainTo");
        List<String> fromComps = PathResolver.normalize(plainFrom);
        List<String> toComps = PathResolver.normalize(plainTo);
        if (fromComps.isEmpty() || toComps.isEmpty()) {
            throw new IOException("cannot rename the root directory");
        }
        PathResolver.Resolved from = pathResolver.resolveParent(plainFrom);
        if (!exists(from.cipherPath)) {
            throw new NoSuchFileException(plainFrom);
        }
        if (fromComps.equals(toComps)) {
            return;
        }
        if (toComps.size() > fromComps.size()
                && toComps.subList(0, fromComps.size()).equals(fromComps)) {
            throw new IOException("cannot move " + plainFrom + " into its own subtree: " + plainTo);
        }
        PathResolver.Resolved to = pathResolver.resolveParent(plainTo);
        if (exists(to.cipherPath)) {
            if (!replaceExisting) {
                throw new FileAlreadyExistsException(plainTo);
            }
            if (store.stat(to.cipherPath).isDirectory()) {
                // A directory can only be replaced when it is empty apart from
                // its gocryptfs.diriv. Verify that before removing anything so a
                // rejected replace leaves the target intact. The empty directory
                // (and its diriv) is then removed explicitly, because an atomic
                // rename cannot replace a directory that still contains its diriv.
                for (CipherNode entry : store.list(to.cipherPath)) {
                    if (!entry.name().equals(Constants.DIR_IV_FILENAME)) {
                        throw new DirectoryNotEmptyException(to.cipherPath);
                    }
                }
                deleteIfExists(store, PathResolver.join(to.cipherPath, Constants.DIR_IV_FILENAME));
                store.delete(to.cipherPath);
                nameManager.removeLongName(to);
            }
            // A non-directory target is replaced atomically by the rename below.
        }
        boolean wroteName = nameManager.prepareLongName(to);
        try {
            store.rename(from.cipherPath, to.cipherPath, replaceExisting);
        } catch (IOException | RuntimeException e) {
            // prepareLongName may have created a long-name support file that no
            // longer has a matching entry; drop it so a failed rename leaves no
            // orphan behind.
            if (wroteName) {
                nameManager.removeLongName(to);
            }
            throw e;
        }
        nameManager.removeLongName(from);
        directoryManager.invalidateDirIvCache(from.cipherPath);
        directoryManager.invalidateDirIvCache(to.cipherPath);
    }

    // ------------------------------------------------------------------
    // Symlinks
    // ------------------------------------------------------------------

    /**
     * Reads and decrypts the target of a cipher-side symlink.
     *
     * @param cipherSymlink the ciphertext symlink name
     * @return the plaintext symlink target
     * @throws IOException on filesystem or decryption errors
     * @throws NullPointerException if {@code cipherSymlink} is {@code null}
     */
    String readSymlink(String cipherSymlink) throws IOException {
        Objects.requireNonNull(cipherSymlink, "cipherSymlink");
        return readSymlink(cipherSymlink, store, contentEnc, nameTransform, plaintextNames);
    }

    /**
     * Reads and decrypts the target of a plaintext symlink path.
     *
     * @param plainPath the plaintext symlink path
     * @return the plaintext symlink target
     * @throws IOException on filesystem or decryption errors
     * @throws NullPointerException if {@code plainPath} is {@code null}
     */
    String readSymlinkTarget(String plainPath) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        PathResolver.Resolved r = pathResolver.resolve(plainPath);
        return readSymlink(r.cipherPath);
    }

    /**
     * Creates a symlink pointing to {@code target}.
     *
     * @param plainPath the plaintext symlink path
     * @param target    the plaintext target
     * @throws IOException on filesystem or encryption errors
     * @throws NullPointerException if {@code plainPath} or {@code target} is {@code null}
     */
    void createSymlink(String plainPath, String target) throws IOException {
        Objects.requireNonNull(plainPath, "plainPath");
        Objects.requireNonNull(target, "target");
        PathResolver.Resolved r = pathResolver.resolveParent(plainPath);
        boolean wroteName = nameManager.prepareLongName(r);
        try {
            String cTarget = encryptSymlinkTarget(target, contentEnc, nameTransform, plaintextNames);
            store.createSymlink(r.cipherPath, cTarget);
        } catch (IOException | RuntimeException e) {
            if (wroteName) {
                nameManager.removeLongName(r);
            }
            throw e;
        }
    }

    /**
     * Encrypts and base64url-encodes a plaintext symlink target.
     *
     * @param target         the plaintext target
     * @param contentEnc     the content-encryption helper
     * @param nameTransform  the name-transform helper
     * @param plaintextNames whether names (and symlink targets) are unencrypted
     * @return the stored (ciphertext) symlink target
     */
    static String encryptSymlinkTarget(String target, ContentEnc contentEnc,
                                       NameTransform nameTransform, boolean plaintextNames) {
        if (plaintextNames || target.isEmpty()) {
            return target;
        }
        byte[] enc = contentEnc.encryptBlock(target.getBytes(StandardCharsets.UTF_8), 0, null);
        return nameTransform.b64Encode(enc);
    }

    /**
     * Reads and decrypts the target of a cipher-side symlink.
     *
     * @param cipherSymlink  the ciphertext symlink name
     * @param store          the ciphertext-side store
     * @param contentEnc     the content-encryption helper
     * @param nameTransform  the name-transform helper
     * @param plaintextNames whether names (and symlink targets) are unencrypted
     * @return the plaintext symlink target
     * @throws IOException on filesystem or decryption errors
     */
    static String readSymlink(String cipherSymlink, CipherStore store, ContentEnc contentEnc,
                              NameTransform nameTransform, boolean plaintextNames)
            throws IOException {
        String target = store.readSymlink(cipherSymlink);
        if (plaintextNames || target.isEmpty()) {
            return target;
        }
        byte[] cData = nameTransform.b64Decode(target);
        try {
            byte[] data = contentEnc.decryptBlock(cData, 0, null);
            return new String(data, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IOException("corrupt symlink target", e);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Deletes a ciphertext entry, ignoring an already-absent entry.
     *
     * @param store the store
     * @param name  the ciphertext path to delete
     * @throws IOException on storage errors other than the entry being absent
     */
    static void deleteIfExists(CipherStore store, String name) throws IOException {
        try {
            store.delete(name);
        } catch (NoSuchFileException ignored) {
            // Already gone.
        }
    }

    /**
     * Returns whether a ciphertext entry exists.
     *
     * @param name the ciphertext path
     * @return {@code true} if the entry exists
     * @throws IOException on storage errors other than the entry being absent
     */
    private boolean exists(String name) throws IOException {
        try {
            store.stat(name);
            return true;
        } catch (NoSuchFileException e) {
            return false;
        }
    }

    /**
     * A streaming, decrypting {@link InputStream} over a {@link CipherFile}.
     *
     * <p>Buffers decrypted data so that {@link java.io.InputStream#read()}
     * works efficiently. Closing the stream closes the underlying cipher file.</p>
     */
    private static final class CipherInputStream extends InputStream {

        /** The size of the decrypted read-ahead buffer. */
        private static final int BUFFER_SIZE = 8192;

        /** The cipher file being read. */
        private final CipherFile cf;

        /** The current plaintext position. */
        private long pos;

        /** The read-ahead buffer. */
        private final byte[] buf = new byte[BUFFER_SIZE];

        /** The current position within the read-ahead buffer. */
        private int bufPos;

        /** The number of valid bytes in the read-ahead buffer. */
        private int bufLen;

        /**
         * Creates a stream over the given cipher file.
         *
         * @param cf the cipher file to read from
         */
        CipherInputStream(CipherFile cf) {
            this.cf = cf;
        }

        /**
         * Reads a single plaintext byte.
         *
         * @return the byte, or {@code -1} at the end of the stream
         * @throws IOException on filesystem errors
         */
        @Override
        public int read() throws IOException {
            if (bufPos >= bufLen && !fill()) {
                return -1;
            }
            pos++;
            return buf[bufPos++] & 0xFF;
        }

        /**
         * Reads plaintext bytes into a range of an array.
         *
         * @param b   the destination buffer
         * @param off the destination offset
         * @param len the maximum number of bytes
         * @return the number of bytes read, or {@code -1} at the end of the stream
         * @throws IOException on filesystem errors
         */
        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            int copied = 0;
            if (bufPos < bufLen) {
                int n = Math.min(len, bufLen - bufPos);
                System.arraycopy(buf, bufPos, b, off, n);
                bufPos += n;
                pos += n;
                copied = n;
                if (copied == len) {
                    return copied;
                }
            }
            int n = cf.read(ByteBuffer.wrap(b, off + copied, len - copied), pos);
            if (n < 0) {
                return copied == 0 ? -1 : copied;
            }
            pos += n;
            return copied + n;
        }

        /**
         * Refills the read-ahead buffer.
         *
         * @return {@code true} if more data was read
         * @throws IOException on filesystem errors
         */
        private boolean fill() throws IOException {
            int n = cf.read(ByteBuffer.wrap(buf), pos);
            if (n <= 0) {
                bufLen = 0;
                return false;
            }
            bufLen = n;
            bufPos = 0;
            return true;
        }

        /**
         * Closes the underlying cipher file and wipes the read-ahead buffer,
         * which holds up to 8 KiB of decrypted plaintext. Calling this method
         * more than once has no effect.
         *
         * @throws IOException on filesystem errors
         */
        @Override
        public void close() throws IOException {
            try {
                cf.close();
            } finally {
                Arrays.fill(buf, (byte) 0);
                bufPos = 0;
                bufLen = 0;
            }
        }
    }
}
