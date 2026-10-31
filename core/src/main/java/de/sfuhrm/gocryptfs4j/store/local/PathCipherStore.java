package de.sfuhrm.gocryptfs4j.store.local;

import de.sfuhrm.gocryptfs4j.crypto.IoUtil;
import de.sfuhrm.gocryptfs4j.store.CipherNode;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

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
        return IoUtil.readBounded(path(name), maxBytes);
    }

    @Override
    public void writeSmall(String name, byte[] data, boolean overwrite) throws IOException {
        Path p = path(name);
        if (overwrite) {
            Files.write(p, data, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
        } else {
            Files.write(p, data, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        }
    }

    @Override
    public CipherNode stat(String name) throws IOException {
        Path p = path(name);
        BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        return node(p.getFileName().toString(), attrs);
    }

    @Override
    public List<CipherNode> list(String dir) throws IOException {
        Path d = path(dir);
        List<CipherNode> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(d)) {
            for (Path p : ds) {
                BasicFileAttributes attrs = Files.readAttributes(p, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
                out.add(node(p.getFileName().toString(), attrs));
            }
        }
        return out;
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
        Files.createFile(path(name));
    }

    @Override
    public void mkdir(String name) throws IOException {
        Files.createDirectory(path(name));
    }

    @Override
    public void delete(String name) throws IOException {
        Files.delete(path(name));
    }

    @Override
    public void rename(String from, String to, boolean replaceExisting) throws IOException {
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
        Files.createSymbolicLink(path(name), Paths.get(target));
    }

    @Override
    public String readSymlink(String name) throws IOException {
        return Files.readSymbolicLink(path(name)).toString();
    }

    @Override
    public void setTimes(String name, @Nullable FileTime lastModifiedTime,
                         @Nullable FileTime lastAccessTime, @Nullable FileTime creationTime)
            throws IOException {
        BasicFileAttributeView view = Files.getFileAttributeView(path(name),
                BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("basic attribute view not supported");
        }
        view.setTimes(lastModifiedTime, lastAccessTime, creationTime);
    }

    @Override
    public SeekableByteChannel open(String name, boolean writable) throws IOException {
        Path p = path(name);
        if (writable) {
            return FileChannel.open(p, StandardOpenOption.READ, StandardOpenOption.WRITE);
        }
        return FileChannel.open(p, StandardOpenOption.READ);
    }

    @Override
    public void close() {
        // No resources to release.
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
