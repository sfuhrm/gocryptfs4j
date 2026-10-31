package de.sfuhrm.gocryptfs4j.store.local;

import de.sfuhrm.gocryptfs4j.crypto.IoUtil;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A {@link CipherStore} decorator (in the sense of
 * {@link java.io.FilterInputStream}) that resolves every ciphertext path
 * through a {@link SecureDirectoryStream}, descending one component at a time
 * with {@code NOFOLLOW_LINKS}. That pins intermediate directories to open
 * directory handles, so a symlink swapped in between the check and the final
 * file access can neither be followed nor redirect the operation outside the
 * cipher root.
 *
 * <p>Operations that {@code SecureDirectoryStream} cannot express
 * ({@link #writeConfig}, {@link #mkdir}, {@link #createSymlink},
 * {@link #readSymlink} and {@link #checkAccess}) are delegated to the wrapped
 * store; the three entry-creating operations first verify the parent through
 * the secure traversal.</p>
 */
final class SecurePathStore implements CipherStore {

    /** The wrapped plain-path store used for operations without a secure variant. */
    private final CipherStore delegate;

    /** The absolute, normalized ciphertext root directory. */
    private final Path root;

    /** The root as a secure directory stream, held open for the store's lifetime. */
    private final SecureDirectoryStream<Path> secureRoot;

    /** Guards {@link #close()} so it is idempotent. */
    private final AtomicBoolean closed = new AtomicBoolean();

    private static final Set<OpenOption> READ_NOFOLLOW =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                    StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)));
    private static final Set<OpenOption> READ_WRITE_NOFOLLOW =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                    StandardOpenOption.READ, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS)));
    private static final Set<OpenOption> WRITE_CREATE_TRUNC_NOFOLLOW =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                    StandardOpenOption.WRITE, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS)));
    private static final Set<OpenOption> WRITE_CREATE_NEW =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                    StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)));

    /**
     * Creates a secure store over the given root, decorating {@code delegate}
     * for the operations that have no secure variant.
     *
     * @param delegate   the plain-path store to fall back to
     * @param root       the absolute, normalized ciphertext root directory
     * @param secureRoot the secure directory stream over {@code root}
     */
    SecurePathStore(CipherStore delegate, Path root, SecureDirectoryStream<Path> secureRoot) {
        this.delegate = delegate;
        this.root = root;
        this.secureRoot = secureRoot;
    }

    @Override
    public String root() {
        return delegate.root();
    }

    @Override
    public byte[] readSmall(String name, int maxBytes) throws IOException {
        Objects.requireNonNull(name, "name");
        try (SecurePath parent = requireParent(name)) {
            BasicFileAttributes attrs = basicAttributes(parent.dir(), parent.name());
            if (!attrs.isRegularFile()) {
                throw new IOException("not a regular file: " + name);
            }
            try (SeekableByteChannel channel = parent.dir().newByteChannel(parent.name(),
                    READ_NOFOLLOW)) {
                return IoUtil.readBounded(Channels.newInputStream(channel), maxBytes);
            }
        }
    }

    @Override
    public void writeSmall(String name, byte[] data, boolean overwrite) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        try (SecurePath parent = requireParent(name)) {
            Set<OpenOption> options = overwrite ? WRITE_CREATE_TRUNC_NOFOLLOW : WRITE_CREATE_NEW;
            try (SeekableByteChannel channel = parent.dir().newByteChannel(parent.name(),
                    options)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
            }
        }
    }

    @Override
    public void writeConfig(String name, byte[] data, boolean overwrite) throws IOException {
        // The config file always lives directly in the (trusted) root directory,
        // so there are no intermediate directories an attacker could swap. The
        // temporary-file + atomic-move dance in the delegate is kept as-is to
        // preserve its atomicity and crash-safety guarantees, which
        // SecureDirectoryStream.move cannot provide.
        delegate.writeConfig(name, data, overwrite);
    }

    @Override
    public CipherNode stat(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        SecurePath parent = resolveParent(name);
        if (parent == null) {
            // The root directory itself.
            BasicFileAttributes attrs = basicAttributes(secureRoot);
            return PlainPathStore.node(PlainPathStore.basename(root), attrs);
        }
        try (SecurePath p = parent) {
            BasicFileAttributes attrs = basicAttributes(p.dir(), p.name());
            return PlainPathStore.node(PlainPathStore.basename(Paths.get(name)), attrs);
        }
    }

    @Override
    public List<CipherNode> list(String dir) throws IOException {
        Objects.requireNonNull(dir, "dir");
        if (components(dir).isEmpty()) {
            return listRoot();
        }
        List<CipherNode> out = new ArrayList<>();
        try (SecurePath directory = resolveDirectory(dir)) {
            for (Path p : directory.dir()) {
                BasicFileAttributes attrs = basicAttributes(directory.dir(), p);
                out.add(PlainPathStore.node(PlainPathStore.basename(p), attrs));
            }
        }
        return out;
    }

    /**
     * Lists the root directory. The cached {@link #secureRoot} cannot be
     * iterated because a {@link SecureDirectoryStream}'s
     * {@link SecureDirectoryStream#iterator() iterator} may only be obtained
     * once, so a fresh handle to the same directory is opened for each listing.
     */
    private List<CipherNode> listRoot() throws IOException {
        List<CipherNode> out = new ArrayList<>();
        try (SecureDirectoryStream<Path> root = secureRoot.newDirectoryStream(
                Paths.get("."), LinkOption.NOFOLLOW_LINKS)) {
            for (Path p : root) {
                BasicFileAttributes attrs = basicAttributes(root, p);
                out.add(PlainPathStore.node(PlainPathStore.basename(p), attrs));
            }
        }
        return out;
    }

    @Override
    public void createFile(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        try (SecurePath parent = requireParent(name);
             SeekableByteChannel channel = parent.dir().newByteChannel(parent.name(),
                     WRITE_CREATE_NEW)) {
            // Creating the channel creates the empty file.
        }
    }

    @Override
    public void mkdir(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        // SecureDirectoryStream has no create-directory operation, so the actual
        // creation is delegated. Walking to the parent first still verifies
        // every intermediate component is a real directory, shrinking the window
        // in which an attacker could swap one for a symlink (but not closing it
        // entirely).
        verifyParent(name);
        delegate.mkdir(name);
    }

    @Override
    public void delete(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        try (SecurePath parent = requireParent(name)) {
            BasicFileAttributes attrs = basicAttributes(parent.dir(), parent.name());
            if (attrs.isDirectory()) {
                parent.dir().deleteDirectory(parent.name());
            } else {
                // deleteFile unlinks without following a symlink, so a symlink
                // entry is removed rather than its target.
                parent.dir().deleteFile(parent.name());
            }
        }
    }

    @Override
    public void rename(String from, String to, boolean replaceExisting) throws IOException {
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        try (SecurePath src = requireParent(from);
             SecurePath dst = requireParent(to)) {
            if (!replaceExisting) {
                // SecureDirectoryStream.move has no replace flag, so the no-replace
                // contract is enforced by checking the target first (with the same
                // unavoidable race as the plain Files.move path).
                try {
                    basicAttributes(dst.dir(), dst.name());
                    throw new FileAlreadyExistsException(Paths.get(to).toString());
                } catch (NoSuchFileException e) {
                    // Target is free.
                }
            }
            src.dir().move(src.name(), dst.dir(), dst.name());
        }
    }

    @Override
    public void createSymlink(String name, String target) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(target, "target");
        // No SecureDirectoryStream API exists for creating symlinks; see
        // {@link #mkdir} for the residual-window rationale.
        verifyParent(name);
        delegate.createSymlink(name, target);
    }

    @Override
    public String readSymlink(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        // No SecureDirectoryStream API exists for reading symlinks.
        verifyParent(name);
        return delegate.readSymlink(name);
    }

    @Override
    public void setTimes(String name, @Nullable FileTime lastModifiedTime,
                         @Nullable FileTime lastAccessTime, @Nullable FileTime creationTime)
            throws IOException {
        Objects.requireNonNull(name, "name");
        try (SecurePath parent = requireParent(name)) {
            BasicFileAttributeView view = parent.dir().getFileAttributeView(parent.name(),
                    BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (view == null) {
                throw new IOException("basic attribute view not supported");
            }
            view.setTimes(lastModifiedTime, lastAccessTime, creationTime);
        }
    }

    @Override
    public CipherChannel open(String name, boolean writable) throws IOException {
        Objects.requireNonNull(name, "name");
        SecurePath parent = requireParent(name);
        SeekableByteChannel channel;
        try {
            channel = parent.dir().newByteChannel(parent.name(),
                    writable ? READ_WRITE_NOFOLLOW : READ_NOFOLLOW);
        } finally {
            // The opened channel is independent of the directory handle, so the
            // handle can be released as soon as the file is open.
            parent.close();
        }
        if (channel instanceof FileChannel) {
            return new FileChannelAdapter((FileChannel) channel);
        }
        // A provider that yields a non-file channel cannot provide force();
        // fall back to the plain path-based open so force() keeps working.
        channel.close();
        return delegate.open(name, writable);
    }

    @Override
    public void checkAccess(String name, AccessMode... modes) throws IOException {
        // No SecureDirectoryStream API exists for access checks. The final
        // component is not followed by the data-access paths above, so the
        // residual risk here is limited to access checks on a path whose
        // intermediate directory has been swapped.
        delegate.checkAccess(name, modes);
    }

    @Override
    public @Nullable PosixFileAttributes posixAttributes(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        try (SecurePath parent = requireParent(name)) {
            PosixFileAttributeView view = parent.dir().getFileAttributeView(parent.name(),
                    PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            return view == null ? null : view.readAttributes();
        }
    }

    @Override
    public void setPosixPermissions(String name, Set<PosixFilePermission> permissions)
            throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(permissions, "permissions");
        try (SecurePath parent = requireParent(name)) {
            posixView(parent).setPermissions(permissions);
        }
    }

    @Override
    public void setPosixOwner(String name, UserPrincipal owner) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(owner, "owner");
        try (SecurePath parent = requireParent(name)) {
            posixView(parent).setOwner(owner);
        }
    }

    @Override
    public void setPosixGroup(String name, GroupPrincipal group) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(group, "group");
        try (SecurePath parent = requireParent(name)) {
            posixView(parent).setGroup(group);
        }
    }

    @Override
    public void close() throws IOException {
        if (closed.compareAndSet(false, true)) {
            secureRoot.close();
        }
    }

    /**
     * Returns the POSIX attribute view of the entry named by a resolved parent
     * handle. The view is only valid while the handle (and its directory
     * stream) is open, so it must be used within the caller's try block.
     *
     * @param parent the resolved parent handle
     * @return the POSIX attribute view
     * @throws UnsupportedOperationException if the backing filesystem has no POSIX support
     */
    private PosixFileAttributeView posixView(SecurePath parent) throws IOException {
        PosixFileAttributeView view = parent.dir().getFileAttributeView(parent.name(),
                PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new UnsupportedOperationException(
                    "POSIX attributes are not supported by the backing filesystem");
        }
        return view;
    }

    /**
     * Splits a ciphertext name into its path components relative to the root.
     *
     * @param name the ciphertext name
     * @return the components, in order, relative to the root; empty for the root
     * @throws IOException if the name is not within the root
     */
    private List<Path> components(String name) throws IOException {
        Path p = Paths.get(name);
        if (!p.isAbsolute()) {
            p = root.resolve(p);
        }
        p = p.normalize();
        Path rel;
        try {
            rel = root.relativize(p);
        } catch (IllegalArgumentException e) {
            throw new IOException("path outside root: " + name, e);
        }
        List<Path> out = new ArrayList<>();
        for (Path c : rel) {
            String component = c.toString();
            // The empty relative path (the root itself) iterates to a single
            // empty component on some providers, so it must be skipped rather
            // than treated as a directory name.
            if (component.isEmpty()) {
                continue;
            }
            if (component.equals("..")) {
                throw new IOException("path outside root: " + name);
            }
            out.add(c);
        }
        return out;
    }

    /**
     * Walks a sequence of intermediate components through the secure root,
     * opening each as a real (non-symlink) directory.
     *
     * @param comps the intermediate components (all but the last)
     * @return the directory handle for the last component, whose {@link #close()}
     *         releases the directory unless it is the cached root
     * @throws IOException if a component is missing, not a directory, or a symlink
     */
    private SecurePath walk(List<Path> comps) throws IOException {
        SecureDirectoryStream<Path> cur = secureRoot;
        boolean owns = false;
        try {
            for (Path c : comps) {
                SecureDirectoryStream<Path> next = cur.newDirectoryStream(c,
                        LinkOption.NOFOLLOW_LINKS);
                if (owns) {
                    cur.close();
                }
                cur = next;
                owns = true;
            }
        } catch (IOException e) {
            if (owns) {
                cur.close();
            }
            throw e;
        }
        return new SecurePath(cur, null, owns);
    }

    /**
     * Resolves a ciphertext name to the directory it names, descending through
     * every component. The returned handle's {@link SecurePath#dir()} is the
     * directory itself.
     */
    private SecurePath resolveDirectory(String name) throws IOException {
        return walk(components(name));
    }

    /**
     * Resolves a ciphertext name to its parent directory plus the final
     * component.
     *
     * @return the parent handle with a non-null name, or {@code null} when
     *         {@code name} is the root itself
     */
    private @Nullable SecurePath resolveParent(String name) throws IOException {
        List<Path> comps = components(name);
        if (comps.isEmpty()) {
            return null;
        }
        Path last = comps.remove(comps.size() - 1);
        SecurePath parent = walk(comps);
        return new SecurePath(parent.dir(), last, parent.owns);
    }

    /**
     * Resolves a ciphertext name to its parent, throwing when the name has no
     * parent (the root itself).
     */
    private SecurePath requireParent(String name) throws IOException {
        SecurePath parent = resolveParent(name);
        if (parent == null) {
            throw new IOException("no parent directory for " + name);
        }
        return parent;
    }

    /**
     * Verifies that every intermediate directory of {@code name} is a real
     * directory, not a symlink. Used as a best-effort hardening for the
     * operations {@code SecureDirectoryStream} cannot perform directly.
     */
    private void verifyParent(String name) throws IOException {
        requireParent(name).close();
    }

    /**
     * Reads the basic attributes of an entry relative to an open directory
     * handle, without following symlinks.
     */
    private static BasicFileAttributes basicAttributes(SecureDirectoryStream<Path> dir, Path name)
            throws IOException {
        BasicFileAttributeView view = dir.getFileAttributeView(name, BasicFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("basic attribute view not supported");
        }
        return view.readAttributes();
    }

    /**
     * Reads the basic attributes of a directory handle itself.
     */
    private static BasicFileAttributes basicAttributes(SecureDirectoryStream<Path> dir)
            throws IOException {
        BasicFileAttributeView view = dir.getFileAttributeView(BasicFileAttributeView.class);
        if (view == null) {
            throw new IOException("basic attribute view not supported");
        }
        return view.readAttributes();
    }

    /**
     * Adapts a {@link FileChannel} to the {@link CipherChannel} contract,
     * delegating {@link #force(boolean)} to {@link FileChannel#force(boolean)}.
     */
    private static final class FileChannelAdapter implements CipherChannel {

        private final FileChannel channel;

        FileChannelAdapter(FileChannel channel) {
            this.channel = channel;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            return channel.read(dst);
        }

        @Override
        public int write(ByteBuffer src) throws IOException {
            return channel.write(src);
        }

        @Override
        public long position() throws IOException {
            return channel.position();
        }

        @Override
        public CipherChannel position(long newPosition) throws IOException {
            channel.position(newPosition);
            return this;
        }

        @Override
        public long size() throws IOException {
            return channel.size();
        }

        @Override
        public CipherChannel truncate(long size) throws IOException {
            channel.truncate(size);
            return this;
        }

        @Override
        public boolean isOpen() {
            return channel.isOpen();
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }

        @Override
        public void force(boolean metaData) throws IOException {
            channel.force(metaData);
        }
    }

    /**
     * A resolved directory handle within the secure root: an open
     * {@link SecureDirectoryStream} plus, for entry operations, the relative
     * name of the final component within that directory. Closing the handle
     * releases the directory stream unless it is the store's cached root.
     */
    private static final class SecurePath implements AutoCloseable {

        private final SecureDirectoryStream<Path> dir;
        private final @Nullable Path name;
        private final boolean owns;

        SecurePath(SecureDirectoryStream<Path> dir, @Nullable Path name, boolean owns) {
            this.dir = dir;
            this.name = name;
            this.owns = owns;
        }

        SecureDirectoryStream<Path> dir() {
            return dir;
        }

        Path name() {
            return Objects.requireNonNull(name, "name");
        }

        @Override
        public void close() throws IOException {
            if (owns) {
                dir.close();
            }
        }
    }
}
