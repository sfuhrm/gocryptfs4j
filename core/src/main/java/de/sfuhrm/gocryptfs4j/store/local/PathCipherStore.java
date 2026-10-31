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
 * A {@link CipherStore} backed by a directory on a {@code java.nio.file}
 * filesystem.
 *
 * <p>Ciphertext paths are absolute filesystem paths rooted at the store's root
 * directory. File content is opened with a {@link FileChannel}, which natively
 * supports the random-access operations the encrypted file layer needs.</p>
 */
public final class PathCipherStore implements CipherStore {

    /** The absolute, normalized ciphertext root directory. */
    private final Path root;

    /** The root name, the absolute root directory path as a string. */
    private final String rootName;

    /**
     * Creates a store over the given ciphertext root directory.
     *
     * @param root the ciphertext root directory
     * @throws NullPointerException if {@code root} is {@code null}
     */
    public PathCipherStore(Path root) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.rootName = this.root.toString();
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
        try (InputStream in = Files.newInputStream(p)) {
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
    private static String basename(Path p) {
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
    private static CipherNode node(String name, BasicFileAttributes attrs) {
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
            Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING);
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
        FileChannel ch = writable
                ? FileChannel.open(p, StandardOpenOption.READ, StandardOpenOption.WRITE)
                : FileChannel.open(p, StandardOpenOption.READ);
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
