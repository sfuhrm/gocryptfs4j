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
 * an ordinary path, without any extra protection against symlinks in
 * intermediate directories. This is the fallback backing of
 * {@link PathCipherStore} for filesystems that do not support
 * {@link java.nio.file.SecureDirectoryStream}; on such filesystems
 * {@link SecurePathStore} decorates this class to add that protection.
 */
final class PlainPathStore implements CipherStore {

    /** The root name, the absolute root directory path as a string. */
    private final String rootName;

    /**
     * Creates a store over the given ciphertext root.
     *
     * @param rootName the absolute root directory path
     */
    PlainPathStore(String rootName) {
        this.rootName = rootName;
    }

    @Override
    public String root() {
        return rootName;
    }

    /**
     * Converts a ciphertext name into a {@link Path}.
     *
     * @param name the ciphertext name (an absolute path string)
     * @return the corresponding path
     */
    private static Path path(String name) {
        return Paths.get(name);
    }

    @Override
    public byte[] readSmall(String name, int maxBytes) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = path(name);
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
        Path p = path(name);
        if (overwrite) {
            Files.write(p, data, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
        } else {
            Files.write(p, data, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }
    }

    @Override
    public void writeConfig(String name, byte[] data, boolean overwrite) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(data, "data");
        Path p = path(name).toAbsolutePath();
        Path dir = p.getParent();
        if (dir == null) {
            throw new IOException("cannot determine parent directory of " + p);
        }
        // Write to a temporary file in the same directory, flush it to disk and
        // move it into place, so a crash or a full disk never leaves the config
        // file truncated or half-written. New files get mode 0400, matching gocryptfs.
        Path temp = Files.createTempFile(dir, ".gocryptfs-", ".tmp");
        boolean moved = false;
        try {
            try (FileChannel channel = FileChannel.open(temp,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            try {
                Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("r--------"));
            } catch (UnsupportedOperationException e) {
                // Non-POSIX filesystem: keep the default permissions.
            }
            if (overwrite) {
                Files.move(temp, p, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } else {
                // No ATOMIC_MOVE here: with it, rename(2) would replace the
                // target and skip the create-new check. Without it, Files.move
                // throws FileAlreadyExistsException if the file appeared in the
                // meantime, preserving the create-new contract.
                Files.move(temp, p);
            }
            moved = true;
        } finally {
            if (!moved) {
                Files.deleteIfExists(temp);
            }
        }
    }

    @Override
    public CipherNode stat(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = path(name);
        BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        return node(basename(p), attrs);
    }

    @Override
    public List<CipherNode> list(String dir) throws IOException {
        Objects.requireNonNull(dir, "dir");
        Path d = path(dir);
        List<CipherNode> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(d)) {
            for (Path p : ds) {
                BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
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
        Files.createFile(path(name));
    }

    @Override
    public void mkdir(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        Files.createDirectory(path(name));
    }

    @Override
    public void delete(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        Files.delete(path(name));
    }

    @Override
    public void rename(String from, String to, boolean replaceExisting) throws IOException {
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        Path src = path(from);
        Path dst = path(to);
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
            Files.move(src, dst);
        }
    }

    @Override
    public void createSymlink(String name, String target) throws IOException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(target, "target");
        Files.createSymbolicLink(path(name), Paths.get(target));
    }

    @Override
    public String readSymlink(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        return Files.readSymbolicLink(path(name)).toString();
    }

    @Override
    public void setTimes(String name, @Nullable FileTime lastModifiedTime,
                         @Nullable FileTime lastAccessTime, @Nullable FileTime creationTime)
            throws IOException {
        Objects.requireNonNull(name, "name");
        BasicFileAttributeView view = Files.getFileAttributeView(path(name),
                BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("basic attribute view not supported");
        }
        view.setTimes(lastModifiedTime, lastAccessTime, creationTime);
    }

    @Override
    public CipherChannel open(String name, boolean writable) throws IOException {
        Objects.requireNonNull(name, "name");
        Path p = path(name);
        // Do not follow symlinks so a symlink swapped into the ciphertext
        // directory cannot redirect the read/write to an arbitrary file.
        FileChannel ch = writable
                ? FileChannel.open(p, StandardOpenOption.READ, StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS)
                : FileChannel.open(p, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        return new FileChannelAdapter(ch);
    }

    @Override
    public void checkAccess(String name, AccessMode... modes) throws IOException {
        Objects.requireNonNull(name, "name");
        path(name).getFileSystem().provider().checkAccess(path(name), modes);
    }

    @Override
    public @Nullable PosixFileAttributes posixAttributes(String name) throws IOException {
        Objects.requireNonNull(name, "name");
        PosixFileAttributeView view = Files.getFileAttributeView(path(name),
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
    private PosixFileAttributeView posixView(String name) {
        PosixFileAttributeView view = Files.getFileAttributeView(path(name),
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
