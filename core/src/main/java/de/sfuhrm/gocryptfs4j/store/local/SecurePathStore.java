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
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
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
 * ({@link #mkdir}, {@link #createSymlink}, {@link #readSymlink}, a
 * non-replacing {@link #rename}, a create-new {@link #writeSmall} and
 * {@link #checkAccess}) are delegated to the wrapped store. Every one of them
 * still resolves its parent through the secure traversal so that it addresses
 * the same pinned directory as the rest of the store, and that parent handle is
 * kept open for the duration of the delegated operation. Because NIO exposes no
 * {@code mkdirat}/{@code symlinkat}/{@code readlinkat}/{@code linkat}/
 * {@code renameat2}, the delegated operation is then a path-based syscall: the
 * traversal rejects a symlink that is already in place as an intermediate
 * component, but a directory swapped or moved between the traversal and that
 * syscall remains a residual window (see {@link #requireParent}).</p>
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
    public AutoCloseable lockRoot() throws IOException {
        return RootFileLock.acquire(root);
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
        if (!overwrite) {
            // SecureDirectoryStream.move is rename(2): it always replaces an
            // existing target, so enforcing the no-replace contract by checking
            // the target first and then moving is racy. A file created in the
            // meantime (for example a gocryptfs.diriv) would be silently
            // replaced, leaving every name in the directory undecryptable.
            // Delegate to the path-based store, which publishes the temporary
            // file with a hard link where the filesystem supports one, so the
            // create-new contract is enforced atomically. The parent is resolved
            // through the secure traversal and kept pinned while the delegated
            // syscall runs; see the class comment for the residual window.
            try (SecurePath parent = requireParent(name)) {
                delegate.writeSmall(name, data, false);
            }
            return;
        }
        try (SecurePath parent = requireParent(name)) {
            writeSecure(parent, data, null);
        }
    }

    @Override
    public void writeConfig(String name, byte[] data, boolean overwrite) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        if (overwrite) {
            // The config file always lives directly in the (trusted) root
            // directory. Write it through the pinned root handle with the same
            // temporary-file + atomic-move dance as writeSmall, so it lands in
            // the same directory the rest of the store addresses and a crash
            // never leaves it truncated. New files get mode 0400, matching
            // gocryptfs.
            try (SecurePath parent = requireParent(name)) {
                writeSecure(parent, data, PosixFilePermissions.fromString("r--------"));
            }
            return;
        }
        // Create-new semantics cannot be expressed with SecureDirectoryStream
        // (move is rename(2) and always replaces); delegate to the path-based
        // store's hard-link publish, keeping the parent pinned.
        try (SecurePath parent = requireParent(name)) {
            delegate.writeConfig(name, data, false);
        }
    }

    /**
     * Writes {@code data} to the entry addressed by {@code parent} through the
     * pinned directory handle: to a temporary file that is flushed and moved
     * into place, so a crash never leaves the target truncated or half-written.
     *
     * @param parent      the pinned parent handle plus the target name
     * @param data        the content to write
     * @param permissions the POSIX permissions to apply to the new file, or
     *                    {@code null} to keep the temporary file's defaults
     * @throws IOException on filesystem errors
     */
    private void writeSecure(SecurePath parent, byte[] data,
                              @Nullable Set<PosixFilePermission> permissions) throws IOException {
        Path temp = Paths.get(".gocryptfs-" + UUID.randomUUID() + ".tmp");
        boolean moved = false;
        try {
            try (SeekableByteChannel channel = parent.dir().newByteChannel(temp,
                    WRITE_CREATE_NEW)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                if (channel instanceof FileChannel) {
                    ((FileChannel) channel).force(true);
                }
            }
            if (permissions != null) {
                PosixFileAttributeView view = parent.dir().getFileAttributeView(temp,
                        PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
                if (view != null) {
                    view.setPermissions(permissions);
                }
            }
            parent.dir().move(temp, parent.dir(), parent.name());
            moved = true;
        } finally {
            if (!moved) {
                try {
                    parent.dir().deleteFile(temp);
                } catch (NoSuchFileException ignored) {
                    // Already gone.
                }
            }
        }
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
                BasicFileAttributes attrs;
                try {
                    attrs = basicAttributes(directory.dir(), p);
                } catch (NoSuchFileException e) {
                    // The entry disappeared between the directory listing and
                    // reading its attributes (a concurrent delete or rename):
                    // skip it rather than aborting the whole listing.
                    continue;
                }
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
                BasicFileAttributes attrs;
                try {
                    attrs = basicAttributes(root, p);
                } catch (NoSuchFileException e) {
                    // The entry disappeared between the directory listing and
                    // reading its attributes (a concurrent delete or rename):
                    // skip it rather than aborting the whole listing.
                    continue;
                }
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
        // creation is delegated. The parent is resolved through the secure
        // traversal and kept pinned while the delegated path-based syscall runs;
        // see the class comment for the residual window.
        try (SecurePath parent = requireParent(name)) {
            delegate.mkdir(name);
        }
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
        if (!replaceExisting) {
            // SecureDirectoryStream.move is rename(2): it always replaces an
            // existing target, so enforcing no-replace by checking the target
            // and then moving is racy. Delegate to the path-based store, whose
            // Files.move without REPLACE_EXISTING fails with
            // FileAlreadyExistsException instead of silently replacing. Both
            // parents are resolved through the secure traversal and kept pinned
            // while the delegated syscall runs; see the class comment for the
            // residual window.
            try (SecurePath src = requireParent(from);
                 SecurePath dst = requireParent(to)) {
                delegate.rename(from, to, false);
            }
            return;
        }
        try (SecurePath src = requireParent(from);
             SecurePath dst = requireParent(to)) {
            src.dir().move(src.name(), dst.dir(), dst.name());
        }
    }

    @Override
    public void createSymlink(String name, String target) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(target, "target");
        // No SecureDirectoryStream API exists for creating symlinks; see the
        // class comment for the residual window.
        try (SecurePath parent = requireParent(name)) {
            delegate.createSymlink(name, target);
        }
    }

    @Override
    public String readSymlink(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        // No SecureDirectoryStream API exists for reading symlinks; see the
        // class comment for the residual window.
        try (SecurePath parent = requireParent(name)) {
            return delegate.readSymlink(name);
        }
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
        Path p = root.getFileSystem().getPath(name);
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
     * parent (the root itself). The returned handle pins the parent directory:
     * it descends from the cached {@link #secureRoot} with {@code NOFOLLOW_LINKS},
     * so a symlink already in place as an intermediate component is rejected, and
     * the directory is held open for the duration of the operation. Closing the
     * handle releases the directory unless it is the cached root. The residual
     * window is that the delegated path-based syscall re-resolves the parent's
     * path rather than using the open directory descriptor, so a directory
     * swapped or moved after this call still redirects that syscall; NIO exposes
     * no {@code *at} primitive to close it.
     */
    private SecurePath requireParent(String name) throws IOException {
        SecurePath parent = resolveParent(name);
        if (parent == null) {
            throw new IOException("no parent directory for " + name);
        }
        return parent;
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
