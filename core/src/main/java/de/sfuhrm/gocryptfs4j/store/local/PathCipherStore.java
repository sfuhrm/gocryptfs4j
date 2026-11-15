package de.sfuhrm.gocryptfs4j.store.local;

import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.file.AccessMode;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A {@link CipherStore} backed by a directory on a {@code java.nio.file}
 * filesystem.
 *
 * <p>Ciphertext paths are absolute filesystem paths rooted at the store's root
 * directory. File content is opened with a channel that natively supports the
 * random-access operations the encrypted file layer needs.</p>
 *
 * <p>This class is a thin facade that selects the actual backing at
 * construction time: when the filesystem provides {@link SecureDirectoryStream}
 * support, every operation is delegated to a {@link SecurePathStore} that
 * resolves paths component-by-component without following symlinks; otherwise a
 * plain {@link PlainPathStore} is used, which still confines every path to the
 * root directory and rejects symlinks at the final component.</p>
 *
 * <p>The selection fails closed: a filesystem that genuinely has no
 * {@link SecureDirectoryStream} (for example the default Windows provider or a
 * zip filesystem) silently falls back to the plain store, but a failure while
 * opening the secure stream &mdash; a transient {@code EMFILE}, a permission
 * error, or a root that is missing or not a directory &mdash; is reported
 * instead of being silently downgraded. Callers that must not run without
 * symlink protection can check {@link #isSymlinkSafe()} or use
 * {@link #requireSymlinkSafe(Path)}.</p>
 *
 * <p>A root directory that is itself a symlink is followed to its canonical
 * real path before the backing is selected, so a symlinked root (for example
 * {@code ~/Dropbox/vault}) is not silently downgraded to the plain store.</p>
 */
public final class PathCipherStore implements CipherStore {

    /** The absolute, canonical (symlink-resolved) ciphertext root directory. */
    private final Path root;

    /** The store to which every operation is delegated. */
    private final CipherStore delegate;

    /** Whether the delegate protects against symlinks in intermediate directories. */
    private final boolean symlinkSafe;

    /**
     * Creates a store over the given ciphertext root directory.
     *
     * @param root the ciphertext root directory
     * @throws NullPointerException if {@code root} is {@code null}
     * @throws IOException if {@code root} is not an existing directory or the
     *                     secure directory stream cannot be opened
     */
    public PathCipherStore(Path root) throws IOException {
        this.root = resolveRoot(Objects.requireNonNull(root, "root"));
        this.delegate = createDelegate(this.root);
        this.symlinkSafe = delegate instanceof SecurePathStore;
    }

    /**
     * Creates a store over the given ciphertext root directory, failing if the
     * backing filesystem does not provide symlink-safe
     * ({@link SecureDirectoryStream}) traversal.
     *
     * @param root the ciphertext root directory
     * @return a symlink-safe store
     * @throws NullPointerException if {@code root} is {@code null}
     * @throws IOException if the store cannot be opened symlink-safely
     */
    public static PathCipherStore requireSymlinkSafe(Path root) throws IOException {
        PathCipherStore store = new PathCipherStore(root);
        if (!store.isSymlinkSafe()) {
            closeQuietly(store);
            throw new IOException("the backing filesystem does not support symlink-safe "
                    + "directory traversal: " + store.rootPath());
        }
        return store;
    }

    /**
     * Returns whether this store protects against symlinks in intermediate
     * directories. It is {@code true} when the backing is a
     * {@link SecurePathStore} (the filesystem provides
     * {@link SecureDirectoryStream}) and {@code false} when the plain
     * path-based store is used, for example on Windows or a zip filesystem.
     *
     * @return whether the store is symlink-safe
     */
    public boolean isSymlinkSafe() {
        return symlinkSafe;
    }

    /**
     * Closes a store, suppressing any failure so a rejected open is reported by
     * its original exception.
     *
     * @param store the store to close
     */
    private static void closeQuietly(CipherStore store) {
        try {
            store.close();
        } catch (IOException ignored) {
            // Best effort; the open is already being rejected.
        }
    }

    /**
     * Resolves the ciphertext root to its canonical real path, following
     * symlinks. This lets a root that is itself a symlink (for example
     * {@code ~/Dropbox/vault}) still receive the secure backing instead of
     * silently degrading to the plain path store.
     *
     * @param root the caller-supplied root path
     * @return the canonical real path, or the absolute normalized path when
     *         the root does not exist yet (the constructor then rejects it)
     */
    private static Path resolveRoot(Path root) {
        Path normalized = root.toAbsolutePath().normalize();
        try {
            return normalized.toRealPath();
        } catch (IOException e) {
            // The root does not exist yet (or is a dangling symlink): keep the
            // normalized path so the subsequent directory check can report a
            // precise "not a directory" error.
            return normalized;
        }
    }

    /**
     * Creates a store over the given ciphertext root directory using a
     * caller-supplied secure directory stream for the root. Package-private
     * for testing: it lets tests exercise the secure path on filesystems whose
     * provider does not itself yield a {@link SecureDirectoryStream}.
     *
     * @param root       the ciphertext root directory
     * @param secureRoot the secure directory stream over {@code root}
     */
    PathCipherStore(Path root, SecureDirectoryStream<Path> secureRoot) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.delegate = new SecurePathStore(
                new PlainPathStore(this.root), this.root, secureRoot);
        this.symlinkSafe = true;
    }

    /**
     * Selects the backing store for the given root: a secure decorator when the
     * filesystem supports it, otherwise the plain path-based store.
     *
     * @throws IOException if the root is not a directory or the secure
     *                     directory stream cannot be opened
     */
    private static CipherStore createDelegate(Path root) throws IOException {
        PlainPathStore plain = new PlainPathStore(root);
        SecureDirectoryStream<Path> secureRoot = openSecureRoot(root);
        return secureRoot == null ? plain : new SecurePathStore(plain, root, secureRoot);
    }

    /**
     * Opens the root directory as a {@link SecureDirectoryStream} if the
     * backing filesystem supports it.
     *
     * <p>This fails closed: a missing or non-directory root, or an error while
     * opening the stream (a transient {@code EMFILE}, a permission problem, or
     * a provider that rejects directory streaming) is reported as an
     * {@link IOException} rather than silently downgrading the store to
     * path-based access. Only a provider that successfully returns a plain
     * (non-secure) {@link DirectoryStream} is treated as genuinely not
     * supporting symlink-safe traversal and yields {@code null}.</p>
     *
     * @param root the ciphertext root directory
     * @return a secure directory stream over {@code root}, or {@code null} when
     *         the provider has no {@link SecureDirectoryStream} support
     * @throws IOException if the root is not a directory or the stream cannot
     *                     be opened
     */
    @SuppressWarnings("unchecked")
    private static @Nullable SecureDirectoryStream<Path> openSecureRoot(Path root)
            throws IOException {
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("not a directory: " + root);
        }
        DirectoryStream<Path> ds;
        try {
            ds = Files.newDirectoryStream(root);
        } catch (UnsupportedOperationException e) {
            throw new IOException("directory streaming is not supported: " + root, e);
        }
        // An IOException from newDirectoryStream propagates unchanged: it is a
        // real failure (for example EMFILE or a permission error), not proof
        // that the provider lacks SecureDirectoryStream support.
        if (ds instanceof SecureDirectoryStream<?>) {
            return (SecureDirectoryStream<Path>) ds;
        }
        ds.close();
        // The provider successfully returned a plain DirectoryStream, so it
        // genuinely has no SecureDirectoryStream (for example the default
        // Windows provider or a zip filesystem): fall back to the plain store.
        return null;
    }

    /**
     * Returns the ciphertext root directory as a {@link Path}. This is the
     * local-filesystem location backing this store and is unavailable for
     * non-local stores.
     *
     * @return the ciphertext root directory
     */
    public Path rootPath() {
        return root;
    }

    @Override
    public String root() {
        return delegate.root();
    }

    @Override
    public AutoCloseable lockRoot() throws IOException {
        return RootFileLock.acquire(root);
    }

    @Override
    public byte[] readSmall(String name, int maxBytes) throws IOException {
        return delegate.readSmall(name, maxBytes);
    }

    @Override
    public void writeSmall(String name, byte[] data, boolean overwrite) throws IOException {
        delegate.writeSmall(name, data, overwrite);
    }

    @Override
    public void writeConfig(String name, byte[] data, boolean overwrite) throws IOException {
        delegate.writeConfig(name, data, overwrite);
    }

    @Override
    public CipherNode stat(String name) throws IOException {
        return delegate.stat(name);
    }

    @Override
    public List<CipherNode> list(String dir) throws IOException {
        return delegate.list(dir);
    }

    @Override
    public void createFile(String name) throws IOException {
        delegate.createFile(name);
    }

    @Override
    public void mkdir(String name) throws IOException {
        delegate.mkdir(name);
    }

    @Override
    public void delete(String name) throws IOException {
        delegate.delete(name);
    }

    @Override
    public void rename(String from, String to, boolean replaceExisting) throws IOException {
        delegate.rename(from, to, replaceExisting);
    }

    @Override
    public void createSymlink(String name, String target) throws IOException {
        delegate.createSymlink(name, target);
    }

    @Override
    public String readSymlink(String name) throws IOException {
        return delegate.readSymlink(name);
    }

    @Override
    public void setTimes(String name, @Nullable FileTime lastModifiedTime,
                         @Nullable FileTime lastAccessTime, @Nullable FileTime creationTime)
            throws IOException {
        delegate.setTimes(name, lastModifiedTime, lastAccessTime, creationTime);
    }

    @Override
    public CipherChannel open(String name, boolean writable) throws IOException {
        return delegate.open(name, writable);
    }

    @Override
    public void checkAccess(String name, AccessMode... modes) throws IOException {
        delegate.checkAccess(name, modes);
    }

    @Override
    public @Nullable PosixFileAttributes posixAttributes(String name) throws IOException {
        return delegate.posixAttributes(name);
    }

    @Override
    public void setPosixPermissions(String name, Set<PosixFilePermission> permissions)
            throws IOException {
        delegate.setPosixPermissions(name, permissions);
    }

    @Override
    public void setPosixOwner(String name, UserPrincipal owner) throws IOException {
        delegate.setPosixOwner(name, owner);
    }

    @Override
    public void setPosixGroup(String name, GroupPrincipal group) throws IOException {
        delegate.setPosixGroup(name, group);
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
