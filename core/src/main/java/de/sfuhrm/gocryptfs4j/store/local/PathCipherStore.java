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
 */
public final class PathCipherStore implements CipherStore {

    /** The absolute, normalized ciphertext root directory. */
    private final Path root;

    /** The store to which every operation is delegated. */
    private final CipherStore delegate;

    /**
     * Creates a store over the given ciphertext root directory.
     *
     * @param root the ciphertext root directory
     * @throws NullPointerException if {@code root} is {@code null}
     */
    public PathCipherStore(Path root) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.delegate = createDelegate(this.root);
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
    }

    /**
     * Selects the backing store for the given root: a secure decorator when the
     * filesystem supports it, otherwise the plain path-based store.
     */
    private static CipherStore createDelegate(Path root) {
        PlainPathStore plain = new PlainPathStore(root);
        SecureDirectoryStream<Path> secureRoot = openSecureRoot(root);
        return secureRoot == null ? plain : new SecurePathStore(plain, root, secureRoot);
    }

    /**
     * Opens the root directory as a {@link SecureDirectoryStream} if the
     * backing filesystem supports it, otherwise returns {@code null}.
     *
     * @param root the ciphertext root directory
     * @return a secure directory stream over {@code root}, or {@code null}
     */
    @SuppressWarnings("unchecked")
    private static @Nullable SecureDirectoryStream<Path> openSecureRoot(Path root) {
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            return null;
        }
        try {
            DirectoryStream<Path> ds = Files.newDirectoryStream(root);
            if (ds instanceof SecureDirectoryStream<?>) {
                return (SecureDirectoryStream<Path>) ds;
            }
            ds.close();
        } catch (IOException | UnsupportedOperationException e) {
            // Not a secure provider: fall back to path-based access.
        }
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
