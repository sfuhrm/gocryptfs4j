package de.sfuhrm.gocryptfs4j.store.local;

import de.sfuhrm.gocryptfs4j.crypto.IoUtil;
import de.sfuhrm.gocryptfs4j.store.CipherChannel;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AccessMode;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A {@link CipherStore} over the local filesystem that resolves every name as
 * an ordinary path relative to the store root, rejecting any name that resolves
 * outside the root. This is the fallback backing of {@link PathCipherStore} for
 * filesystems that do not support {@link java.nio.file.SecureDirectoryStream};
 * on such filesystems {@link SecurePathStore} decorates this class to add
 * symlink protection for intermediate directories.
 */
final class PlainPathStore implements CipherStore {

    /** The absolute, normalized ciphertext root directory. */
    private final Path root;

    /**
     * Whether the backing filesystem supports hard links, or {@code null} while
     * it has not been probed yet. The capability is probed once per store, on
     * the first create-new write. Filesystems without hard links (FAT/exFAT,
     * some SMB/FUSE mounts, cloud-sync folders) then use a temporary file plus
     * a non-replacing move instead.
     */
    private volatile @Nullable Boolean hardLinksSupported;

    /**
     * Creates a store over the given ciphertext root.
     *
     * @param root the ciphertext root directory
     */
    PlainPathStore(Path root) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
    }

    @Override
    public String root() {
        return root.toString();
    }

    @Override
    public AutoCloseable lockRoot() throws IOException {
        return RootFileLock.acquire(root);
    }

    /**
     * Resolves a ciphertext name to a path within the root directory.
     *
     * @param name the ciphertext name (an absolute path, or one relative to the root)
     * @return the resolved, normalized absolute path
     * @throws IOException if the name resolves outside the root directory
     */
    private Path resolve(String name) throws IOException {
        Path p = root.getFileSystem().getPath(name);
        if (!p.isAbsolute()) {
            p = root.resolve(p);
        }
        p = p.normalize();
        if (!p.startsWith(root)) {
            throw new IOException("path outside root: " + name);
        }
        return p;
    }

    @Override
    public byte[] readSmall(String name, int maxBytes) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = resolve(name);
        if (!Files.exists(p, LinkOption.NOFOLLOW_LINKS)) {
            throw new NoSuchFileException(p.toString());
        }
        if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("not a regular file: " + p);
        }
        // Open without following symlinks so a symlink swapped in between the
        // check above and the open cannot redirect the read to another file.
        // The regular-file check still runs first because opening a FIFO for
        // reading would otherwise block until a writer appears. Note that this
        // is only a best-effort defense: Java exposes no O_NONBLOCK on open, so
        // an attacker with write access to the ciphertext directory can still
        // swap a FIFO in between the check and the open below and cause this
        // open to block (a denial-of-service, not a data leak).
        try (InputStream in = Files.newInputStream(p, LinkOption.NOFOLLOW_LINKS)) {
            return IoUtil.readBounded(in, maxBytes);
        }
    }

    @Override
    public void writeSmall(String name, byte[] data, boolean overwrite) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        Path p = resolve(name);
        writeAtomically(p, data, overwrite, null);
    }

    @Override
    public void writeJournal(String name, byte[] data) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        Path p = resolve(name);
        boolean existed = Files.exists(p, LinkOption.NOFOLLOW_LINKS);
        // A journal is never user-visible and is discarded if a crash tears it;
        // writing it in place avoids the temporary file, rename and directory
        // fsync of the generic atomic small-file write on every data update.
        try (FileChannel channel = FileChannel.open(p,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
        if (!existed) {
            // Force the new directory entry once, before the associated data
            // write is allowed to reach stable storage.
            fsyncDirectory(p.getParent());
        }
    }

    @Override
    public void writeConfig(String name, byte[] data, boolean overwrite) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        Path p = resolve(name);
        // New files get mode 0400, matching gocryptfs.
        writeAtomically(p, data, overwrite, PosixFilePermissions.fromString("r--------"));
    }

    /**
     * Writes {@code data} to {@code p} atomically: to a temporary file in the
     * same directory that is flushed to disk and moved into place, so a crash or
     * a full disk never leaves the target truncated or half-written. After the
     * move the parent directory is fsynced so the rename itself is durable.
     *
     * @param p           the target path
     * @param data        the content to write
     * @param overwrite   whether to replace an existing file
     * @param permissions the POSIX permissions to apply to a new file, or
     *                    {@code null} to keep the temporary file's default
     * @throws IOException if the file cannot be written, or it exists and
     *                     {@code overwrite} is {@code false}
     */
    private void writeAtomically(Path p, byte[] data, boolean overwrite,
                                 @Nullable Set<PosixFilePermission> permissions)
            throws IOException {
        Path dir = p.getParent();
        if (dir == null) {
            throw new IOException("cannot determine parent directory of " + p);
        }
        Path temp = Files.createTempFile(dir, ".gocryptfs-", ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(temp,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            if (permissions != null) {
                try {
                    Files.setPosixFilePermissions(temp, permissions);
                } catch (UnsupportedOperationException e) {
                    // Non-POSIX filesystem: keep the default permissions.
                }
            }
            if (overwrite) {
                Files.move(temp, p, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } else if (supportsHardLinks()) {
                publishWithHardLink(temp, p);
            } else {
                // The filesystem cannot create hard links. Move the temporary
                // file into place without REPLACE_EXISTING: an existing target
                // still raises FileAlreadyExistsException, but a target created
                // between the move's existence check and rename(2) may be
                // replaced. The content itself is still written crash-safely.
                Files.move(temp, p);
            }
        } finally {
            // After a move the temporary name is gone; after a hard link it is
            // a second name for the published file and must be unlinked.
            Files.deleteIfExists(temp);
        }
        fsyncDirectory(dir);
    }

    /**
     * Publishes a fully written temporary file at the target name by
     * hard-linking it and then unlinking the temporary name. link(2) atomically
     * fails with {@link FileAlreadyExistsException} if the target exists, so the
     * create-new contract holds under concurrency. A plain {@link Files#move}
     * without {@code REPLACE_EXISTING} cannot provide this: on Linux the JDK
     * only stats the target before calling rename(2), which then replaces it, so
     * a target created in between would be silently overwritten.
     *
     * <p>If the probe said hard links work but this particular directory still
     * cannot create one (for example because it is a different mount), the
     * capability is remembered as unsupported and the temporary file is moved
     * into place instead.</p>
     *
     * <p>A crash between the link and the caller's unlink of {@code temp}
     * leaves both names pointing at one inode. The target is still complete
     * and readable; the next writable open removes the hidden temporary alias
     * and, if another alias remains, detaches the opened name (see
     * {@link #repairHardLinks(Path)}).</p>
     *
     * @param temp the fully written temporary file
     * @param p    the target path
     * @throws IOException if the target exists or the file cannot be published
     */
    private void publishWithHardLink(Path temp, Path p) throws IOException {
        try {
            Files.createLink(p, temp);
        } catch (FileAlreadyExistsException e) {
            throw e;
        } catch (IOException | UnsupportedOperationException e) {
            disableHardLinks();
            Files.move(temp, p);
        }
    }

    /**
     * Returns whether the backing filesystem supports hard links, probing it
     * once per store on first use. The probe runs in the store root; a
     * directory on a different mount that still refuses a hard link is caught
     * by {@link #publishWithHardLink} and switches to the fallback too.
     *
     * @return whether hard links are supported
     */
    private boolean supportsHardLinks() {
        Boolean supported = hardLinksSupported;
        if (supported != null) {
            return supported;
        }
        synchronized (this) {
            Boolean probed = hardLinksSupported;
            if (probed == null) {
                probed = probeHardLinks(root);
                hardLinksSupported = probed;
            }
            return probed;
        }
    }

    /**
     * Probes whether hard links can be created in {@code dir} by creating and
     * removing a temporary file and a hard link to it.
     *
     * @param dir the directory to probe
     * @return whether hard links work there
     */
    private static boolean probeHardLinks(Path dir) {
        Path source = null;
        Path link = null;
        try {
            source = Files.createTempFile(dir, ".gocryptfs-probe-", ".tmp");
            link = dir.resolve(source.getFileName().toString() + ".link");
            Files.createLink(link, source);
            return true;
        } catch (IOException | UnsupportedOperationException | SecurityException e) {
            return false;
        } finally {
            if (link != null) {
                try {
                    Files.deleteIfExists(link);
                } catch (IOException | UnsupportedOperationException | SecurityException e) {
                    // Best effort: the probe file is only a temporary artifact.
                }
            }
            if (source != null) {
                try {
                    Files.deleteIfExists(source);
                } catch (IOException | UnsupportedOperationException | SecurityException e) {
                    // Best effort cleanup.
                }
            }
        }
    }

    /**
     * Remembers that the backing filesystem cannot create hard links, so later
     * create-new writes go straight to the non-replacing-move fallback.
     */
    private synchronized void disableHardLinks() {
        hardLinksSupported = Boolean.FALSE;
    }

    /**
     * Best-effort fsync of a directory so that an entry created, deleted or
     * renamed within it becomes durable across power loss. Not all filesystems
     * permit opening a directory; on such filesystems the operation is still
     * atomic, just not forced to stable storage.
     *
     * @param dir the directory to fsync, or {@code null} to do nothing
     */
    static void fsyncDirectory(@Nullable Path dir) {
        if (dir == null) {
            return;
        }
        try (FileChannel channel = FileChannel.open(dir, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException e) {
            // Non-POSIX or read-only filesystems cannot open a directory as a
            // channel; ignore, the atomic move still holds.
        }
    }

    /**
     * Best-effort fsync of the parent directories affected by a rename: the
     * source directory loses an entry and the target directory gains one. When
     * both are the same directory it is forced only once.
     *
     * @param src the source path of the rename
     * @param dst the target path of the rename
     */
    private static void fsyncRenameParents(Path src, Path dst) {
        Path srcDir = src.getParent();
        Path dstDir = dst.getParent();
        if (srcDir == null || srcDir.equals(dstDir)) {
            fsyncDirectory(dstDir);
        } else {
            fsyncDirectory(srcDir);
            fsyncDirectory(dstDir);
        }
    }

    @Override
    public CipherNode stat(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = resolve(name);
        BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        return node(basename(p), attrs);
    }

    @Override
    public List<CipherNode> list(String dir) throws IOException {
        Objects.requireNonNull(dir, "dir");
        Path d = resolve(dir);
        List<CipherNode> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(d)) {
            for (Path p : ds) {
                BasicFileAttributes attrs;
                try {
                    attrs = Files.readAttributes(p, BasicFileAttributes.class,
                            LinkOption.NOFOLLOW_LINKS);
                } catch (NoSuchFileException e) {
                    // The entry disappeared between the directory listing and
                    // reading its attributes (a concurrent delete or rename):
                    // skip it rather than aborting the whole listing.
                    continue;
                }
                out.add(node(basename(p), attrs));
            }
        }
        return out;
    }

    /**
     * Returns the basename of a ciphertext path, or the whole path string when
     * the path has no basename (for example the filesystem root {@code "/"}).
     *
     * @param p the ciphertext path
     * @return the basename, or the path string for the root
     */
    static String basename(Path p) {
        Path fileName = p.getFileName();
        return fileName == null ? p.toString() : fileName.toString();
    }

    /**
     * Builds a {@link CipherNode} from a ciphertext basename and its attributes.
     *
     * @param name  the ciphertext basename
     * @param attrs the attributes
     * @return the node
     */
    static CipherNode node(String name, BasicFileAttributes attrs) {
        CipherNode.Kind kind;
        if (attrs.isDirectory()) {
            kind = CipherNode.Kind.DIRECTORY;
        } else if (attrs.isSymbolicLink()) {
            kind = CipherNode.Kind.SYMLINK;
        } else if (attrs.isRegularFile()) {
            kind = CipherNode.Kind.FILE;
        } else {
            kind = CipherNode.Kind.OTHER;
        }
        return new ImmutableNode(name, kind, attrs.size(), attrs.lastModifiedTime(),
                attrs.lastAccessTime(), attrs.creationTime(), attrs.fileKey());
    }

    @Override
    public void createFile(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = resolve(name);
        Files.createFile(p);
        fsyncDirectory(p.getParent());
    }

    @Override
    public void mkdir(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = resolve(name);
        Files.createDirectory(p);
        fsyncDirectory(p.getParent());
    }

    @Override
    public void delete(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = resolve(name);
        Files.delete(p);
        fsyncDirectory(p.getParent());
    }

    @Override
    public void rename(String from, String to, boolean replaceExisting) throws IOException {
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        Path src = resolve(from);
        Path dst = resolve(to);
        if (replaceExisting) {
            // Replace atomically where the filesystem supports it. A plain
            // REPLACE_EXISTING move falls back to unlink(dst)+rename(2) (or a
            // copy) on some providers, so a failed move could leave the old
            // target deleted. Only give up the atomicity when the filesystem
            // cannot move atomically at all.
            try {
                Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING);
            }
        } else {
            moveNoReplace(src, dst);
        }
        // The rename is only durable once both directories that gained or lost
        // an entry are forced to stable storage.
        fsyncRenameParents(src, dst);
    }

    /**
     * Moves {@code src} to {@code dst} with create-new (no-clobber) semantics.
     *
     * <p>For a regular file the move is performed by hard-linking {@code src}
     * at {@code dst} and then unlinking {@code src}: {@code link(2)} fails with
     * {@code EEXIST} atomically, so a target created concurrently is never
     * silently replaced. {@link Files#move} cannot provide this &mdash; the JDK
     * only stats the target before calling {@code rename(2)}, which then
     * replaces it.</p>
     *
     * <p>A crash between the {@code link(2)} and the unlink of {@code src}
     * leaves both names pointing at one inode. The data is intact, but editing
     * one name would change the other. A later writable open detects the
     * unexpected link count and detaches the opened name, as described in
     * {@link #repairHardLinks(Path)}.</p>
     *
     * <p>Directories and symbolic links cannot be hard-linked, so they fall
     * back to a plain {@code Files.move} whose no-replace check has the
     * residual check-then-rename window: a target that appears between the
     * existence check and the rename is replaced. That window only affects
     * entries an external writer races to create, and cannot be removed through
     * the {@code java.nio.file} API, which exposes neither {@code renameat2}
     * with {@code RENAME_NOREPLACE} nor an atomic no-replace move.</p>
     *
     * @param src the source path
     * @param dst the target path
     * @throws FileAlreadyExistsException if {@code dst} already exists
     * @throws IOException on filesystem errors
     */
    private void moveNoReplace(Path src, Path dst) throws IOException {
        if (Files.isRegularFile(src, LinkOption.NOFOLLOW_LINKS) && supportsHardLinks()) {
            try {
                Files.createLink(dst, src);
            } catch (FileAlreadyExistsException e) {
                throw e;
            } catch (IOException | UnsupportedOperationException | SecurityException e) {
                // Hard links do not work on this particular directory (for
                // example a different mount). Remember it and fall back to the
                // non-atomic move below.
                disableHardLinks();
                Files.move(src, dst);
                return;
            }
            // The link was created atomically (it would have failed had dst
            // existed), so the source name is now redundant; unlinking it
            // completes the move. A failure here leaves both names in place,
            // matching coreutils mv, with the data preserved under dst.
            Files.delete(src);
            return;
        }
        Files.move(src, dst);
    }

    @Override
    public void createSymlink(String name, String target) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(target, "target");
        Path p = resolve(name);
        Files.createSymbolicLink(p, Paths.get(target));
        fsyncDirectory(p.getParent());
    }

    @Override
    public String readSymlink(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        return Files.readSymbolicLink(resolve(name)).toString();
    }

    @Override
    public void setTimes(String name, @Nullable FileTime lastModifiedTime,
                         @Nullable FileTime lastAccessTime, @Nullable FileTime creationTime)
            throws IOException {
        Objects.requireNonNull(name, "name");
        BasicFileAttributeView view = Files.getFileAttributeView(resolve(name),
                BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("basic attribute view not supported");
        }
        view.setTimes(lastModifiedTime, lastAccessTime, creationTime);
    }

    @Override
    public CipherChannel open(String name, boolean writable) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = resolve(name);
        if (writable) {
            repairHardLinks(p);
        }
        // Do not follow symlinks so a symlink swapped into the ciphertext
        // directory cannot redirect the read/write to an arbitrary file.
        FileChannel ch = writable
                ? FileChannel.open(p, StandardOpenOption.READ, StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS)
                : FileChannel.open(p, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        return new FileChannelAdapter(ch);
    }

    /**
     * Returns the hard-link count of a ciphertext file, or {@code 1} when the
     * backing provider cannot report one.
     *
     * <p>The count is read through the {@code unix:nlink} attribute. Providers
     * without the unix attribute view (for example Windows or zip filesystems)
     * cannot have left a hard-link duplicate behind, so they are treated as
     * having a single link.</p>
     *
     * @param p the ciphertext file path
     * @return the hard-link count, or {@code 1} if it is unavailable
     */
    static long linkCount(Path p) {
        try {
            Object value = Files.getAttribute(p, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
            if (value instanceof Number) {
                return ((Number) value).longValue();
            }
        } catch (IOException | UnsupportedOperationException
                 | IllegalArgumentException | SecurityException e) {
            // No unix attribute view or no permission to read it: skip repair.
        }
        return 1L;
    }

    /**
     * Repairs a ciphertext file left with more than one hard link by a crash
     * between {@code link(2)} and the following unlink.
     *
     * <p>A create-new publish leaves a hidden {@code .gocryptfs-*.tmp} name
     * behind. Those names are removed. A no-replace rename instead leaves the
     * source and target names behind; which one is authoritative cannot be
     * recovered, so the name being opened is copied onto a fresh inode and
     * atomically moved into place. Both names then keep their data and later
     * writes through one no longer change the other. A repair failure is
     * ignored: it must not make an otherwise readable file unopenable.</p>
     *
     * @param p the ciphertext file being opened for writing
     */
    private void repairHardLinks(Path p) throws IOException {
        if (linkCount(p) <= 1) {
            return;
        }
        Path dir = p.getParent();
        boolean removed = removeTemporaryAliases(p);
        if (removed) {
            fsyncDirectory(dir);
        }
        if (linkCount(p) <= 1 || dir == null) {
            return;
        }
        try {
            detachHardLink(p, dir);
        } catch (IOException e) {
            // Best effort: keeping the file readable is more important than a
            // repair that the backing filesystem cannot perform.
        }
        fsyncDirectory(dir);
    }

    /**
     * Copies {@code p} to a fresh inode in {@code dir} and atomically replaces
     * {@code p} with it. The original inode stays linked under the other name,
     * so both names keep their data but no longer share later edits.
     *
     * @param p   the ciphertext file to detach
     * @param dir the file's parent directory
     * @throws IOException on filesystem errors
     */
    private static void detachHardLink(Path p, Path dir) throws IOException {
        Path temp = Files.createTempFile(dir, ".gocryptfs-repair-", ".tmp");
        boolean moved = false;
        try {
            try {
                Files.copy(p, temp, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.COPY_ATTRIBUTES, LinkOption.NOFOLLOW_LINKS);
            } catch (UnsupportedOperationException e) {
                Files.copy(p, temp, StandardCopyOption.REPLACE_EXISTING,
                        LinkOption.NOFOLLOW_LINKS);
            }
            try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
                channel.force(true);
            }
            try {
                Files.move(temp, p, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, p, StandardCopyOption.REPLACE_EXISTING);
            }
            moved = true;
        } finally {
            if (!moved) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException e) {
                    // Best effort cleanup.
                }
            }
        }
    }

    /**
     * Removes hidden temporary names that are hard links to {@code p}, as left
     * by a create-new publish that crashed between linking and unlinking the
     * temporary file.
     *
     * @param p the ciphertext file being repaired
     * @return whether any temporary alias was removed
     */
    private static boolean removeTemporaryAliases(Path p) {
        Path dir = p.getParent();
        if (dir == null) {
            return false;
        }
        Object key;
        try {
            key = Files.readAttributes(p, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS).fileKey();
        } catch (IOException e) {
            return false;
        }
        if (key == null) {
            return false;
        }
        boolean removed = false;
        try (DirectoryStream<Path> aliases =
                     Files.newDirectoryStream(dir, ".gocryptfs-*.tmp")) {
            for (Path alias : aliases) {
                if (alias.equals(p)) {
                    continue;
                }
                try {
                    BasicFileAttributes attrs = Files.readAttributes(alias,
                            BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    if (key.equals(attrs.fileKey())) {
                        Files.delete(alias);
                        removed = true;
                    }
                } catch (NoSuchFileException e) {
                    // Removed concurrently.
                } catch (IOException e) {
                    // Best effort: leave the alias rather than fail the open.
                }
            }
        } catch (IOException e) {
            // Best effort: the detach below still removes the aliasing.
        }
        return removed;
    }

    @Override
    public void checkAccess(String name, AccessMode... modes) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = resolve(name);
        // The provider's access check follows a final-component symlink. Refuse
        // the link itself instead, matching the no-follow behavior of every
        // other entry operation in this store.
        if (Files.isSymbolicLink(p)) {
            throw new IOException("symbolic link: " + p);
        }
        p.getFileSystem().provider().checkAccess(p, modes);
    }

    @Override
    public @Nullable PosixFileAttributes posixAttributes(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        PosixFileAttributeView view = Files.getFileAttributeView(resolve(name),
                PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        return view == null ? null : view.readAttributes();
    }

    @Override
    public void setPosixPermissions(String name, Set<PosixFilePermission> permissions)
            throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(permissions, "permissions");
        posixView(name).setPermissions(permissions);
    }

    @Override
    public void setPosixOwner(String name, UserPrincipal owner) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(owner, "owner");
        posixView(name).setOwner(owner);
    }

    @Override
    public void setPosixGroup(String name, GroupPrincipal group) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(group, "group");
        posixView(name).setGroup(group);
    }

    /**
     * Returns the POSIX attribute view of a ciphertext path.
     *
     * @param name the ciphertext path
     * @return the POSIX attribute view
     * @throws UnsupportedOperationException if the backing filesystem has no POSIX support
     */
    private PosixFileAttributeView posixView(String name) throws IOException {
        PosixFileAttributeView view = Files.getFileAttributeView(resolve(name),
                PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new UnsupportedOperationException(
                    "POSIX attributes are not supported by the backing filesystem");
        }
        return view;
    }

    @Override
    public void close() {
        // No resources to release.
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
     * An immutable {@link CipherNode} implementation.
     */
    private static final class ImmutableNode implements CipherNode {

        /** The ciphertext name. */
        private final String name;

        /** The entry kind. */
        private final Kind kind;

        /** The ciphertext size. */
        private final long size;

        /** The last-modified time. */
        private final FileTime lastModifiedTime;

        /** The last-access time. */
        private final FileTime lastAccessTime;

        /** The creation time. */
        private final FileTime creationTime;

        /** The file key, or {@code null}. */
        private final @Nullable Object fileKey;

        /**
         * Creates a node.
         *
         * @param name             the ciphertext name
         * @param kind             the entry kind
         * @param size             the ciphertext size
         * @param lastModifiedTime the last-modified time
         * @param lastAccessTime   the last-access time
         * @param creationTime     the creation time
         * @param fileKey          the file key, or {@code null}
         */
        ImmutableNode(String name, Kind kind, long size, FileTime lastModifiedTime,
                      FileTime lastAccessTime, FileTime creationTime, @Nullable Object fileKey) {
            this.name = name;
            this.kind = kind;
            this.size = size;
            this.lastModifiedTime = lastModifiedTime;
            this.lastAccessTime = lastAccessTime;
            this.creationTime = creationTime;
            this.fileKey = fileKey;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public Kind kind() {
            return kind;
        }

        @Override
        public long size() {
            return size;
        }

        @Override
        public FileTime lastModifiedTime() {
            return lastModifiedTime;
        }

        @Override
        public FileTime lastAccessTime() {
            return lastAccessTime;
        }

        @Override
        public FileTime creationTime() {
            return creationTime;
        }

        @Override
        public @Nullable Object fileKey() {
            return fileKey;
        }
    }
}
