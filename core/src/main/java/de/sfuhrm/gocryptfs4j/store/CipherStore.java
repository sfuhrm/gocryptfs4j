package de.sfuhrm.gocryptfs4j.store;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.file.AccessMode;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Set;

/**
 * A ciphertext-side storage backend for a gocryptfs filesystem.
 *
 * <p>{@code de.sfuhrm.gocryptfs4j.core.GocryptFs} performs all name and content
 * encryption on top of a {@link CipherStore}; it never touches
 * {@code java.nio.file} itself. The store exposes exactly the operations the
 * gocryptfs on-disk format needs: reading and writing the small control files
 * ({@code gocryptfs.conf}, {@code gocryptfs.diriv}, long-name {@code .name}
 * files), listing and inspecting directories, creating, deleting and renaming
 * entries, and opening file content for random access.</p>
 *
 * <p>Names are {@code '/'}-separated ciphertext paths rooted at
 * {@link #root()}, for example {@code "a/b/c"}. The root name itself is
 * returned by {@link #root()} and is opaque: a local store returns an absolute
 * filesystem path, while a remote store returns whatever identifier it uses
 * internally (for example a bucket and prefix). A store is not required to be
 * hierarchical; a flat object store may encode the path in each object's key.</p>
 *
 * <p>Implementations should be safe for concurrent use by a single
 * {@code GocryptFs} instance. A {@link CipherStore} is {@link AutoCloseable};
 * whether {@link #close()} releases external resources (for example network
 * connections) is up to the implementation. A caller that passes its own store
 * to {@code GocryptFs} retains ownership and should close it when done.</p>
 */
public interface CipherStore extends AutoCloseable {

    /**
     * Returns the ciphertext root name. All other names passed to this store are
     * relative to, and prefixed by, this root.
     *
     * @return the ciphertext root name
     */
    String root();

    /**
     * Reads a small ciphertext control file, refusing to buffer more than
     * {@code maxBytes} bytes.
     *
     * <p>Control files are attacker-modifiable and must never be buffered
     * without a size limit, so a corrupt file cannot cause an out-of-memory
     * condition.</p>
     *
     * @param name     the ciphertext path of the control file
     * @param maxBytes the maximum number of bytes to accept
     * @return the file contents, at most {@code maxBytes} bytes
     * @throws IOException if the file cannot be read or exceeds {@code maxBytes}
     */
    byte[] readSmall(String name, int maxBytes) throws IOException;

    /**
     * Writes a small ciphertext control file.
     *
     * @param name      the ciphertext path of the control file
     * @param data      the content to write
     * @param overwrite whether to replace an existing file
     * @throws IOException if the file cannot be written, or it exists and
     *                     {@code overwrite} is {@code false}
     */
    void writeSmall(String name, byte[] data, boolean overwrite) throws IOException;

    /**
     * Returns the attributes of a single ciphertext entry.
     *
     * @param name the ciphertext path of the entry
     * @return the entry's attributes
     * @throws IOException if the entry cannot be inspected
     */
    CipherNode stat(String name) throws IOException;

    /**
     * Lists the entries of a ciphertext directory.
     *
     * @param dir the ciphertext directory path
     * @return the directory entries, in no particular order
     * @throws IOException if the directory cannot be listed
     */
    List<CipherNode> list(String dir) throws IOException;

    /**
     * Creates an empty ciphertext file, failing if it already exists.
     *
     * @param name the ciphertext path to create
     * @throws IOException on storage errors or if the entry already exists
     */
    void createFile(String name) throws IOException;

    /**
     * Creates a ciphertext directory, failing if it already exists.
     *
     * @param name the ciphertext path to create
     * @throws IOException on storage errors or if the entry already exists
     */
    void mkdir(String name) throws IOException;

    /**
     * Deletes a ciphertext file, symlink or empty directory.
     *
     * @param name the ciphertext path to delete
     * @throws IOException on storage errors
     */
    void delete(String name) throws IOException;

    /**
     * Renames (moves) a ciphertext entry within the store.
     *
     * @param from            the source ciphertext path
     * @param to              the target ciphertext path
     * @param replaceExisting whether an existing target may be replaced
     * @throws IOException on storage errors
     */
    void rename(String from, String to, boolean replaceExisting) throws IOException;

    /**
     * Creates a symbolic link at {@code name} pointing to {@code target}.
     *
     * @param name   the ciphertext symlink path
     * @param target the (already encrypted) symlink target
     * @throws IOException on storage errors
     */
    void createSymlink(String name, String target) throws IOException;

    /**
     * Reads the target of a ciphertext symlink.
     *
     * @param name the ciphertext symlink path
     * @return the (still encrypted) symlink target
     * @throws IOException on storage errors
     */
    String readSymlink(String name) throws IOException;

    /**
     * Sets the times of a ciphertext entry. Any {@code null} time is left
     * unchanged.
     *
     * @param name             the ciphertext path
     * @param lastModifiedTime the last-modified time, or {@code null}
     * @param lastAccessTime   the last-access time, or {@code null}
     * @param creationTime     the creation time, or {@code null}
     * @throws IOException on storage errors
     */
    void setTimes(String name, @Nullable FileTime lastModifiedTime,
                  @Nullable FileTime lastAccessTime, @Nullable FileTime creationTime)
            throws IOException;

    /**
     * Opens a ciphertext file for random access.
     *
     * <p>Stores that cannot update the middle of an object (for example object
     * stores) should return a channel that buffers the whole object locally and
     * writes it back on close. The returned channel supports the
     * {@link CipherChannel} operations used by the encrypted file layer:
     * positioned read, positioned write, {@code size()}, {@code truncate(long)}
     * and {@code force(boolean)}.</p>
     *
     * @param name     the ciphertext file path
     * @param writable whether the file should be opened for writing
     * @return the opened channel
     * @throws IOException on storage errors
     */
    CipherChannel open(String name, boolean writable) throws IOException;

    /**
     * Checks access to a ciphertext entry. Existence (no modes) is assumed to
     * have been verified by the caller; stores that cannot evaluate
     * read/write/execute modes throw {@link UnsupportedOperationException}.
     *
     * @param name  the ciphertext path
     * @param modes the access modes to check, or none to check existence
     * @throws IOException on storage errors or if access is denied
     */
    default void checkAccess(String name, AccessMode... modes) throws IOException {
        if (modes.length != 0) {
            throw new UnsupportedOperationException(
                    "access checks are not supported by this store");
        }
    }

    /**
     * Returns the POSIX attributes of a ciphertext entry, or {@code null} if
     * the store has no POSIX support.
     *
     * @param name the ciphertext path
     * @return the POSIX attributes, or {@code null}
     * @throws IOException on storage errors
     */
    default @Nullable PosixFileAttributes posixAttributes(String name) throws IOException {
        return null;
    }

    /**
     * Sets the POSIX permissions of a ciphertext entry.
     *
     * @param name        the ciphertext path
     * @param permissions the new permissions
     * @throws UnsupportedOperationException if the store has no POSIX support
     * @throws IOException on storage errors
     */
    default void setPosixPermissions(String name, Set<PosixFilePermission> permissions)
            throws IOException {
        throw new UnsupportedOperationException(
                "POSIX permissions are not supported by this store");
    }

    /**
     * Sets the POSIX owner of a ciphertext entry.
     *
     * @param name  the ciphertext path
     * @param owner the new owner
     * @throws UnsupportedOperationException if the store has no POSIX support
     * @throws IOException on storage errors
     */
    default void setPosixOwner(String name, UserPrincipal owner) throws IOException {
        throw new UnsupportedOperationException(
                "POSIX owner is not supported by this store");
    }

    /**
     * Sets the POSIX group of a ciphertext entry.
     *
     * @param name  the ciphertext path
     * @param group the new group
     * @throws UnsupportedOperationException if the store has no POSIX support
     * @throws IOException on storage errors
     */
    default void setPosixGroup(String name, GroupPrincipal group) throws IOException {
        throw new UnsupportedOperationException(
                "POSIX group is not supported by this store");
    }

    /**
     * Releases any resources held by this store. Implementations make this
     * idempotent.
     *
     * @throws IOException on storage errors while closing
     */
    @Override
    void close() throws IOException;
}
