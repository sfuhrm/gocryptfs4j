package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.DirEntry;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.core.CipherFile;
import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link FileSystemProvider} for gocryptfs cipher directories.
 *
 * <p>Register via {@code META-INF/services/java.nio.file.spi.FileSystemProvider}
 * to use {@code FileSystems.newFileSystem(URI.create("gocryptfs:///"), env)}, or
 * instantiate directly. The environment must contain {@code cipherDir} (a
 * {@link Path} or {@link String}) and either {@code password} (a {@code char[]})
 * for password-protected filesystems or {@code fido2Token} (a
 * {@link Fido2Token}) for FIDO2-protected ones.</p>
 */
public final class GocryptFsProvider extends FileSystemProvider {

    /** The URI scheme handled by this provider. */
    public static final String SCHEME = "gocryptfs";

    private final Map<String, GocryptFsFileSystem> filesystems = new ConcurrentHashMap<>();

    /** Creates a gocryptfs filesystem provider. */
    public GocryptFsProvider() {
    }

    /**
     * Opens a filesystem directly, without a URI.
     *
     * @param cipherDir the ciphertext directory
     * @param password  the password to unlock the master key with
     * @return the opened filesystem
     * @throws IOException on filesystem errors
     * @throws NullPointerException if {@code cipherDir} or {@code password} is {@code null}
     */
    public FileSystem newFileSystem(Path cipherDir, char[] password) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        Objects.requireNonNull(password, "password");
        return register(cipherDir, GocryptFs.open(cipherDir, password));
    }

    /**
     * Opens a FIDO2-protected filesystem directly, without a URI.
     *
     * @param cipherDir the ciphertext directory
     * @param token     the FIDO2 token implementation to unlock the master key with
     * @return the opened filesystem
     * @throws IOException on filesystem errors or if the token interaction fails
     * @throws NullPointerException if {@code cipherDir} or {@code token} is {@code null}
     */
    public FileSystem newFileSystem(Path cipherDir, Fido2Token token) throws IOException {
        Objects.requireNonNull(cipherDir, "cipherDir");
        Objects.requireNonNull(token, "token");
        return register(cipherDir, GocryptFs.open(cipherDir, token));
    }

    private FileSystem register(Path cipherDir, GocryptFs core) {
        String key = cipherDir.toAbsolutePath().normalize().toString();
        GocryptFsFileSystem fs = new GocryptFsFileSystem(this, core, key);
        GocryptFsFileSystem existing = filesystems.putIfAbsent(key, fs);
        if (existing != null) {
            // Do not leak the freshly opened key material for a filesystem that
            // is already open under this provider.
            core.close();
            throw new FileSystemAlreadyExistsException(key);
        }
        return fs;
    }

    @Override
    public String getScheme() {
        return SCHEME;
    }

    /**
     * Opens a filesystem from a {@code gocryptfs} URI.
     *
     * <p>The environment must contain {@code cipherDir} and either {@code password}
     * (a {@code char[]}) or {@code fido2Token} (a {@link Fido2Token}).</p>
     *
     * @throws NullPointerException if {@code uri} is {@code null}
     * @throws IllegalArgumentException if the scheme is not {@code gocryptfs}, the
     *                                  environment lacks {@code cipherDir}, lacks both
     *                                  {@code password} and {@code fido2Token}, contains
     *                                  both, or an option has the wrong type
     */
    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        Objects.requireNonNull(uri, "uri");
        if (!SCHEME.equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("uri scheme is not '" + SCHEME + "': " + uri);
        }
        Object cipherDir = env == null ? null : env.get("cipherDir");
        Object password = env == null ? null : env.get("password");
        Object fido2Token = env == null ? null : env.get("fido2Token");
        if (cipherDir == null) {
            throw new IllegalArgumentException("environment must contain 'cipherDir'");
        }
        Path dir = cipherDir instanceof Path
                ? (Path) cipherDir : Paths.get(cipherDir.toString());
        if (password != null && fido2Token != null) {
            throw new IllegalArgumentException(
                    "environment must contain either 'password' or 'fido2Token', not both");
        }
        if (password != null) {
            if (!(password instanceof char[])) {
                throw new IllegalArgumentException("password must be a char[]");
            }
            return newFileSystem(dir, (char[]) password);
        }
        if (fido2Token != null) {
            if (!(fido2Token instanceof Fido2Token)) {
                throw new IllegalArgumentException("fido2Token must be a Fido2Token");
            }
            return newFileSystem(dir, (Fido2Token) fido2Token);
        }
        throw new IllegalArgumentException("environment must contain 'password' or 'fido2Token'");
    }

    /**
     * Returns the filesystem for a {@code gocryptfs} URI.
     *
     * @throws NullPointerException if {@code uri} is {@code null}
     */
    @Override
    public FileSystem getFileSystem(URI uri) {
        Objects.requireNonNull(uri, "uri");
        // The key is percent-encoded in the authority (it contains '/' for
        // absolute cipher paths), so use the raw authority, not getHost()
        // which returns null for percent-encoded authorities.
        String authority = uri.getRawAuthority();
        GocryptFsFileSystem fs = authority == null
                ? null : filesystems.get(GocryptFsFileSystem.urlDecode(authority));
        if (fs == null) {
            throw new java.nio.file.FileSystemNotFoundException("no filesystem for " + uri);
        }
        return fs;
    }

    /**
     * Returns the path for a {@code gocryptfs} URI.
     *
     * @throws NullPointerException if {@code uri} is {@code null}
     */
    @Override
    public Path getPath(URI uri) {
        Objects.requireNonNull(uri, "uri");
        FileSystem fs = getFileSystem(uri);
        String path = uri.getPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        return fs.getPath(path);
    }

    void remove(GocryptFsFileSystem fs) {
        filesystems.remove(fs.key(), fs);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static GocryptFsPath toAbsolute(Path path) {
        if (!(path instanceof GocryptFsPath)) {
            throw new IllegalArgumentException("not a gocryptfs path: " + path);
        }
        return (GocryptFsPath) path.toAbsolutePath();
    }

    private static GocryptFs core(Path path) {
        return ((GocryptFsFileSystem) path.getFileSystem()).core();
    }

    /** Returns whether the given options request that symbolic links not be followed. */
    private static boolean noFollow(LinkOption... options) {
        for (LinkOption option : options) {
            if (option == LinkOption.NOFOLLOW_LINKS) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolves {@code path} to an absolute path, following symbolic links unless
     * {@link LinkOption#NOFOLLOW_LINKS} is given.
     */
    private static GocryptFsPath resolve(Path path, LinkOption... options) throws IOException {
        GocryptFsPath p = toAbsolute(path);
        return noFollow(options) ? p : (GocryptFsPath) p.toRealPath();
    }

    // ------------------------------------------------------------------
    // Channels, streams
    // ------------------------------------------------------------------

    /**
     * Opens or creates a byte channel.
     *
     * <p>{@link StandardOpenOption#SYNC} and {@link StandardOpenOption#DSYNC}
     * force the encrypted file after every write. {@link StandardOpenOption#DELETE_ON_CLOSE}
     * deletes the plaintext file when the channel is closed. The creation
     * {@code attrs} are applied to a newly created file.
     * {@link StandardOpenOption#SPARSE} is accepted but ignored: the encrypted
     * format always materializes whole blocks, so sparse files cannot be
     * produced.</p>
     *
     * @throws NullPointerException if {@code path} or {@code options} is {@code null}
     */
    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options,
                                              FileAttribute<?>... attrs) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(options, "options");
        GocryptFsPath p = resolve(path);
        GocryptFs fs = core(p);
        GocryptFs.Resolved r = fs.resolve(p.toString());

        boolean create = options.contains(StandardOpenOption.CREATE);
        boolean createNew = options.contains(StandardOpenOption.CREATE_NEW);
        boolean read = options.contains(StandardOpenOption.READ);
        boolean append = options.contains(StandardOpenOption.APPEND);
        boolean write = options.contains(StandardOpenOption.WRITE) || append;
        boolean truncate = options.contains(StandardOpenOption.TRUNCATE_EXISTING);
        boolean deleteOnClose = options.contains(StandardOpenOption.DELETE_ON_CLOSE);
        if (!read && !write) {
            read = true;
        }

        boolean exists = java.nio.file.Files.exists(r.cipherPath, LinkOption.NOFOLLOW_LINKS);
        boolean created = false;
        if (createNew && exists) {
            throw new FileAlreadyExistsException(p.toString());
        }
        if ((create || createNew) && !exists) {
            fs.createFile(p.toString());
            created = true;
        } else if (!exists) {
            throw new NoSuchFileException(p.toString());
        }

        CipherFile cf = fs.openCipherFile(r.cipherPath, write);
        long position = 0;
        if (truncate && write) {
            cf.truncate(0);
        }
        if (append) {
            position = cf.plainSize();
        }
        if (created) {
            // Applied after opening so that restrictive modes (for example
            // read-only permissions) do not prevent the channel from opening.
            try {
                applyAttributes(p, attrs);
            } catch (IOException | RuntimeException e) {
                cf.close();
                throw e;
            }
        }
        GocryptFsFileChannel.Sync sync = options.contains(StandardOpenOption.SYNC)
                ? GocryptFsFileChannel.Sync.FULL
                : options.contains(StandardOpenOption.DSYNC)
                        ? GocryptFsFileChannel.Sync.DATA
                        : GocryptFsFileChannel.Sync.NONE;
        GocryptFsFileChannel.CloseAction onClose = deleteOnClose
                ? () -> deleteOnClose(fs, p)
                : null;
        return new GocryptFsFileChannel(cf, read, write, position, sync, onClose);
    }

    /** Deletes {@code path}, ignoring an already-deleted file. */
    private static void deleteOnClose(GocryptFs fs, GocryptFsPath path) throws IOException {
        try {
            fs.delete(path.toString());
        } catch (NoSuchFileException e) {
            // The file is already gone; delete-on-close is satisfied.
        }
    }

    /**
     * Applies the given file attributes to an existing path, best-effort (the
     * encrypted format cannot set them atomically at creation time).
     */
    private static void applyAttributes(GocryptFsPath path, FileAttribute<?>... attrs)
            throws IOException {
        for (FileAttribute<?> attr : attrs) {
            Objects.requireNonNull(attr, "attr");
            setAttributeValue(path, attr.name(), attr.value());
        }
    }

    /**
     * Opens a directory stream.
     *
     * @throws NullPointerException if {@code dir} is {@code null}
     */
    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir,
                                                    DirectoryStream.Filter<? super Path> filter)
            throws IOException {
        Objects.requireNonNull(dir, "dir");
        GocryptFsPath d = toAbsolute(dir);
        GocryptFsPath target = (GocryptFsPath) d.toRealPath();
        GocryptFs fs = core(target);
        List<Path> entries = new ArrayList<>();
        for (DirEntry e : fs.list(target.toString())) {
            Path child = d.resolve(e.plainName());
            if (filter == null || filter.accept(child)) {
                entries.add(child);
            }
        }
        return new GocryptFsDirectoryStream(entries);
    }

    /**
     * Creates a directory.
     *
     * @throws NullPointerException if {@code dir} is {@code null}
     */
    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        Objects.requireNonNull(dir, "dir");
        GocryptFsPath d = toAbsolute(dir);
        core(d).mkdir(d.toString());
        applyAttributes(d, attrs);
    }

    /**
     * Deletes a file, symlink or empty directory.
     *
     * @throws NullPointerException if {@code path} is {@code null}
     */
    @Override
    public void delete(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        GocryptFsPath p = toAbsolute(path);
        core(p).delete(p.toString());
    }

    // ------------------------------------------------------------------
    // Symbolic links
    // ------------------------------------------------------------------

    /**
     * Creates a symbolic link pointing to {@code target}.
     *
     * <p>The target is stored as given and need not exist; a relative target is
     * resolved against the link's parent directory when the link is followed.</p>
     *
     * @throws NullPointerException if {@code link} or {@code target} is {@code null}
     */
    @Override
    public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs)
            throws IOException {
        Objects.requireNonNull(link, "link");
        Objects.requireNonNull(target, "target");
        GocryptFsPath l = toAbsolute(link);
        core(l).createSymlink(l.toString(), target.toString());
    }

    /**
     * Reads the target of a symbolic link.
     *
     * @throws NullPointerException if {@code link} is {@code null}
     * @throws java.nio.file.NotLinkException if {@code link} is not a symbolic link
     */
    @Override
    public Path readSymbolicLink(Path link) throws IOException {
        Objects.requireNonNull(link, "link");
        GocryptFsPath l = toAbsolute(link);
        String target = core(l).readSymlinkTarget(l.toString());
        return l.getFileSystem().getPath(target);
    }

    // ------------------------------------------------------------------
    // Copy / move
    // ------------------------------------------------------------------

    /**
     * Copies a file, symbolic link or directory tree.
     *
     * <p>Symbolic links are followed unless {@link LinkOption#NOFOLLOW_LINKS} is
     * given. With {@link StandardCopyOption#COPY_ATTRIBUTES} the times and, on
     * POSIX systems, the permissions, owner and group are copied to the target.
     * Symbolic links are reproduced as links and never receive attributes.</p>
     *
     * @throws NullPointerException if {@code source} or {@code target} is {@code null}
     */
    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(target, "target");
        Set<CopyOption> opts = options.length == 0
                ? Collections.<CopyOption>emptySet()
                : new HashSet<>(Arrays.asList(options));
        boolean replace = opts.contains(StandardCopyOption.REPLACE_EXISTING);
        boolean copyAttributes = opts.contains(StandardCopyOption.COPY_ATTRIBUTES);

        GocryptFsPath s = toAbsolute(source);
        if (!opts.contains(LinkOption.NOFOLLOW_LINKS)) {
            s = (GocryptFsPath) s.toRealPath();
        }
        GocryptFsPath t = toAbsolute(target);
        GocryptFs fs = core(s);

        if (replace && exists(t)) {
            deleteRecursively(t);
        } else if (!replace && exists(t)) {
            throw new FileAlreadyExistsException(t.toString());
        }

        DirEntry se = fs.stat(s.toString());
        if (se.isDirectory()) {
            fs.mkdir(t.toString());
            for (DirEntry child : fs.list(s.toString())) {
                copy(s.resolve(child.plainName()), t.resolve(child.plainName()), options);
            }
            if (copyAttributes) {
                copyAttributes(s, t, false);
            }
        } else if (se.isSymbolicLink()) {
            fs.createSymlink(t.toString(), fs.readSymlinkTarget(s.toString()));
            if (copyAttributes) {
                copySymlinkAttributes(s, t);
            }
        } else {
            fs.createFile(t.toString());
            try (InputStream in = fs.openRead(s.toString());
                 OutputStream out = fs.openWrite(t.toString())) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            }
            if (copyAttributes) {
                copyAttributes(s, t, false);
            }
        }
    }

    /**
     * Copies the basic (and, if available, POSIX) attributes of {@code source} to
     * {@code target}. The times are set last so that earlier metadata changes do
     * not affect them. Permissions are not copied for symbolic links, whose
     * permissions are not settable; owner, group and times are.
     *
     * @param symlink whether both paths are symbolic links
     */
    private static void copyAttributes(GocryptFsPath source, GocryptFsPath target,
                                       boolean symlink) throws IOException {
        BasicFileAttributes basic = java.nio.file.Files.readAttributes(source,
                BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        PosixFileAttributeView posixView = java.nio.file.Files.getFileAttributeView(target,
                PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posixView != null) {
            PosixFileAttributes posix = java.nio.file.Files.readAttributes(source,
                    PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            posixView.setOwner(posix.owner());
            posixView.setGroup(posix.group());
            if (!symlink) {
                posixView.setPermissions(posix.permissions());
            }
        }
        java.nio.file.Files.getFileAttributeView(target, BasicFileAttributeView.class,
                        LinkOption.NOFOLLOW_LINKS)
                .setTimes(basic.lastModifiedTime(), basic.lastAccessTime(), basic.creationTime());
    }

    /**
     * Best-effort copy of symbolic-link attributes. Some platforms (for example
     * JDK 11 on Linux) cannot set symbolic-link timestamps or ownership; like the
     * JDK's own copy, such failures are ignored so that the link is still copied.
     */
    private static void copySymlinkAttributes(GocryptFsPath source, GocryptFsPath target) {
        try {
            copyAttributes(source, target, true);
        } catch (IOException | UnsupportedOperationException e) {
            // Symbolic-link attributes are not settable on this platform.
        }
    }

    /**
     * Moves a file or directory tree.
     *
     * <p>The move never follows symbolic links: a symbolic link is moved as a
     * link. {@link StandardCopyOption#COPY_ATTRIBUTES} is honored.</p>
     *
     * @throws NullPointerException if {@code source} or {@code target} is {@code null}
     */
    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(target, "target");
        Set<CopyOption> opts = options.length == 0
                ? Collections.<CopyOption>emptySet()
                : new HashSet<>(Arrays.asList(options));
        if (opts.contains(StandardCopyOption.ATOMIC_MOVE)) {
            throw new AtomicMoveNotSupportedException(source.toString(), target.toString(),
                    "atomic moves are not supported");
        }
        if (toAbsolute(source).equals(toAbsolute(target))) {
            return;
        }
        List<CopyOption> copyOptions = new ArrayList<>(opts);
        copyOptions.add(LinkOption.NOFOLLOW_LINKS);
        copy(source, target, copyOptions.toArray(new CopyOption[0]));
        deleteRecursively(toAbsolute(source));
    }

    private void deleteRecursively(Path p) throws IOException {
        GocryptFs fs = core(p);
        DirEntry e = fs.stat(p.toString());
        if (e.isDirectory()) {
            for (DirEntry c : fs.list(p.toString())) {
                deleteRecursively(p.resolve(c.plainName()));
            }
        }
        fs.delete(p.toString());
    }

    private static boolean exists(Path p) throws IOException {
        try {
            core(p).stat(p.toString());
            return true;
        } catch (NoSuchFileException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Attributes
    // ------------------------------------------------------------------

    /**
     * Tests whether two paths locate the same file.
     *
     * @throws NullPointerException if {@code path} or {@code path2} is {@code null}
     */
    @Override
    public boolean isSameFile(Path path, Path path2) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(path2, "path2");
        GocryptFsPath a = resolve(path);
        GocryptFsPath b = resolve(path2);
        if (a.getFileSystem() != b.getFileSystem()) {
            return false;
        }
        if (a.equals(b)) {
            return true;
        }
        Object ka = core(a).stat(a.toString()).fileKey();
        Object kb = core(b).stat(b.toString()).fileKey();
        return ka != null && ka.equals(kb);
    }

    /**
     * Tests whether a path is considered hidden.
     *
     * @throws NullPointerException if {@code path} is {@code null}
     */
    @Override
    public boolean isHidden(Path path) {
        Objects.requireNonNull(path, "path");
        Path name = path.getFileName();
        return name != null && name.toString().startsWith(".");
    }

    /**
     * Returns the file store of a path.
     *
     * @throws NullPointerException if {@code path} is {@code null}
     */
    @Override
    public FileStore getFileStore(Path path) {
        Objects.requireNonNull(path, "path");
        return new GocryptFsFileStore((GocryptFsFileSystem) path.getFileSystem());
    }

    /**
     * Checks access to a path.
     *
     * <p>Access is evaluated against the backing cipher file, whose POSIX
     * permissions are exposed as the plaintext permissions, so {@code READ},
     * {@code WRITE} and {@code EXECUTE} are all honored.</p>
     *
     * @throws NullPointerException if {@code path} is {@code null}
     */
    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        Objects.requireNonNull(path, "path");
        GocryptFsPath p = resolve(path);
        Path cipherPath = core(p).stat(p.toString()).cipherPath();
        cipherPath.getFileSystem().provider().checkAccess(cipherPath, modes);
    }

    /**
     * Returns a file attribute view.
     *
     * @throws NullPointerException if {@code path} or {@code type} is {@code null}
     */
    @Override
    @SuppressWarnings("unchecked")
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type,
                                                                LinkOption... options) {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(type, "type");
        GocryptFsFileSystem fs = (GocryptFsFileSystem) path.getFileSystem();
        boolean follow = !noFollow(options);
        if (type == BasicFileAttributeView.class) {
            return (V) new GocryptFsBasicFileAttributeView(fs, toAbsolute(path), follow);
        }
        if (type == PosixFileAttributeView.class) {
            return fs.supportsPosix()
                    ? (V) new GocryptFsPosixFileAttributeView(fs, toAbsolute(path), follow)
                    : null;
        }
        if (type == FileOwnerAttributeView.class) {
            return fs.supportsPosix()
                    ? (V) new GocryptFsOwnerFileAttributeView(fs, toAbsolute(path), follow)
                    : null;
        }
        return null;
    }

    /**
     * Reads a file's attributes.
     *
     * @throws NullPointerException if {@code path} or {@code type} is {@code null}
     * @throws UnsupportedOperationException if the attribute type is not supported
     */
    @Override
    @SuppressWarnings("unchecked")
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type,
                                                            LinkOption... options)
            throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(type, "type");
        GocryptFsPath p = resolve(path, options);
        if (type == BasicFileAttributes.class) {
            return (A) new GocryptFsFileAttributes(core(p).stat(p.toString()));
        }
        if (type == PosixFileAttributes.class) {
            return (A) readPosixAttributes(p);
        }
        throw new UnsupportedOperationException("unsupported attribute type: " + type);
    }

    /**
     * Reads a set of attributes by name.
     *
     * <p>The {@code attributes} string has the form {@code [view:]attribute-list}
     * where {@code view} defaults to {@code basic} and {@code attribute-list} is a
     * comma separated list of attribute names. The special name {@code *} selects
     * all attributes of the view. The {@code basic}, {@code posix} and
     * {@code owner} views are supported.</p>
     *
     * @throws NullPointerException if {@code path} or {@code attributes} is {@code null}
     * @throws UnsupportedOperationException if the requested attribute view is not available
     * @throws IllegalArgumentException if no attribute or an unrecognized attribute is specified
     */
    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options)
            throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(attributes, "attributes");
        int colon = attributes.indexOf(':');
        String view = colon < 0 ? "basic" : attributes.substring(0, colon);
        GocryptFsPath p = resolve(path, options);
        switch (view) {
            case "basic":
                return basicAttributes(
                        new GocryptFsFileAttributes(core(p).stat(p.toString())), attributes);
            case "posix":
                return posixAttributes(readPosixAttributes(p), attributes);
            case "owner":
                return ownerAttributes(readPosixAttributes(p).owner(), attributes);
            default:
                throw new UnsupportedOperationException("view '" + view + "' is not supported");
        }
    }

    /** The names of all attributes of the basic view, in a stable order. */
    private static final List<String> BASIC_ATTRIBUTES = Arrays.asList(
            "size", "creationTime", "lastModifiedTime", "lastAccessTime",
            "isRegularFile", "isDirectory", "isSymbolicLink", "isOther", "fileKey");

    /** The names of all attributes of the POSIX view: the basic names plus owner/group/permissions. */
    private static final List<String> POSIX_ATTRIBUTES = posixAttributeNames();

    private static List<String> posixAttributeNames() {
        List<String> names = new ArrayList<>(BASIC_ATTRIBUTES);
        names.add("owner");
        names.add("group");
        names.add("permissions");
        return Collections.unmodifiableList(names);
    }

    /**
     * Reads basic attributes from a directory entry by their specification string.
     *
     * @param entry      the directory entry to read from
     * @param attributes the {@code [view:]attribute-list} specification
     * @return the requested attribute values, keyed by their bare names
     * @throws UnsupportedOperationException if the requested view is not the basic view
     * @throws IllegalArgumentException if no attribute or an unrecognized attribute is specified
     */
    static Map<String, Object> basicAttributes(DirEntry entry, String attributes) {
        return basicAttributes(new GocryptFsFileAttributes(entry), attributes);
    }

    private static Map<String, Object> basicAttributes(BasicFileAttributes attrs,
                                                       String specification) {
        String names = stripView(specification, "basic");
        Map<String, Object> result = new HashMap<>();
        for (String token : names.split(",")) {
            if (token.equals("*")) {
                for (String attribute : BASIC_ATTRIBUTES) {
                    result.put(attribute, basicAttribute(attrs, attribute));
                }
            } else {
                result.put(token, basicAttribute(attrs, token));
            }
        }
        return result;
    }

    /**
     * Reads POSIX attributes by their specification string.
     *
     * @param attrs         the POSIX attributes to read from
     * @param specification the {@code [view:]attribute-list} specification
     * @return the requested attribute values, keyed by their bare names
     * @throws UnsupportedOperationException if the requested view is not the POSIX view
     * @throws IllegalArgumentException if an unrecognized attribute is specified
     */
    static Map<String, Object> posixAttributes(GocryptFsPosixFileAttributes attrs,
                                                String specification) {
        String names = stripView(specification, "posix");
        Map<String, Object> result = new HashMap<>();
        for (String token : names.split(",")) {
            if (token.equals("*")) {
                for (String attribute : POSIX_ATTRIBUTES) {
                    result.put(attribute, posixAttribute(attrs, attribute));
                }
            } else {
                result.put(token, posixAttribute(attrs, token));
            }
        }
        return result;
    }

    /**
     * Reads the owner attribute by its specification string.
     *
     * @param owner         the owner principal
     * @param specification the {@code [view:]attribute-list} specification
     * @return the requested attribute values, keyed by their bare names
     * @throws UnsupportedOperationException if the requested view is not the owner view
     * @throws IllegalArgumentException if an unrecognized attribute is specified
     */
    static Map<String, Object> ownerAttributes(UserPrincipal owner, String specification) {
        String names = stripView(specification, "owner");
        Map<String, Object> result = new HashMap<>();
        for (String token : names.split(",")) {
            if (token.equals("*") || token.equals("owner")) {
                result.put("owner", owner);
            } else {
                throw new IllegalArgumentException("'owner:" + token + "' is not recognized");
            }
        }
        return result;
    }

    /**
     * Strips the optional {@code view:} prefix from an attribute specification
     * and validates that the named view is {@code expected}.
     *
     * @param specification the {@code [view:]name} or {@code [view:]name-list} string
     * @param expected      the required view name
     * @return the part after the optional {@code view:} prefix
     * @throws UnsupportedOperationException if a different view is named
     */
    private static String stripView(String specification, String expected) {
        int colon = specification.indexOf(':');
        if (colon < 0) {
            return specification;
        }
        String view = specification.substring(0, colon);
        if (!expected.equals(view)) {
            throw new UnsupportedOperationException("view '" + view + "' is not supported");
        }
        return specification.substring(colon + 1);
    }

    private static Object basicAttribute(BasicFileAttributes attrs, String name) {
        switch (name) {
            case "size":
                return attrs.size();
            case "creationTime":
                return attrs.creationTime();
            case "lastModifiedTime":
                return attrs.lastModifiedTime();
            case "lastAccessTime":
                return attrs.lastAccessTime();
            case "isDirectory":
                return attrs.isDirectory();
            case "isRegularFile":
                return attrs.isRegularFile();
            case "isSymbolicLink":
                return attrs.isSymbolicLink();
            case "isOther":
                return attrs.isOther();
            case "fileKey":
                return attrs.fileKey();
            default:
                throw new IllegalArgumentException("'" + name + "' is not recognized");
        }
    }

    private static Object posixAttribute(GocryptFsPosixFileAttributes attrs, String name) {
        switch (name) {
            case "owner":
                return attrs.owner();
            case "group":
                return attrs.group();
            case "permissions":
                return attrs.permissions();
            default:
                return basicAttribute(attrs, name);
        }
    }

    /**
     * Reads the POSIX attributes of a plaintext path, taking the basic attributes
     * (and thus the plaintext size) from the gocryptfs view and owner, group and
     * permissions from the backing cipher file.
     *
     * @throws UnsupportedOperationException if the backing filesystem has no POSIX support
     */
    static GocryptFsPosixFileAttributes readPosixAttributes(GocryptFsPath path) throws IOException {
        DirEntry entry = core(path).stat(path.toString());
        PosixFileAttributes delegate = posixView(entry.cipherPath()).readAttributes();
        return new GocryptFsPosixFileAttributes(new GocryptFsFileAttributes(entry),
                delegate.owner(), delegate.group(), delegate.permissions());
    }

    /**
     * Returns the POSIX attribute view of a backing cipher file.
     *
     * @throws UnsupportedOperationException if the backing filesystem has no POSIX support
     */
    static PosixFileAttributeView posixView(Path cipherPath) throws IOException {
        PosixFileAttributeView view = java.nio.file.Files.getFileAttributeView(cipherPath,
                PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new UnsupportedOperationException(
                    "POSIX attributes are not supported by the backing filesystem");
        }
        return view;
    }

    /**
     * Sets a file attribute by name.
     *
     * <p>The {@code attribute} string has the form {@code [view:]attribute-name}
     * where {@code view} defaults to {@code basic}. The basic view accepts
     * {@code lastModifiedTime}, {@code lastAccessTime} and {@code creationTime};
     * the POSIX view additionally accepts {@code permissions}, {@code owner} and
     * {@code group}; the owner view accepts {@code owner}.</p>
     *
     * @throws NullPointerException if {@code path} or {@code attribute} is {@code null}
     * @throws UnsupportedOperationException if the requested attribute view is not available
     * @throws IllegalArgumentException if the attribute is not recognized or is not settable
     */
    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options)
            throws IOException {
        setAttributeValue(path, attribute, value, options);
    }

    @SuppressWarnings("unchecked")
    private static void setAttributeValue(Path path, String attribute, Object value,
                                          LinkOption... options) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(attribute, "attribute");
        int colon = attribute.indexOf(':');
        String view = colon < 0 ? "basic" : attribute.substring(0, colon);
        String name = colon < 0 ? attribute : attribute.substring(colon + 1);
        switch (view) {
            case "basic":
                setBasicAttribute(path, name, value, options);
                return;
            case "owner":
                if (!name.equals("owner")) {
                    throw new IllegalArgumentException("'owner:" + name + "' is not recognized");
                }
                newOwnerView(path, options).setOwner((UserPrincipal) value);
                return;
            case "posix":
                setPosixAttribute(path, name, value, options);
                return;
            default:
                throw new UnsupportedOperationException("view '" + view + "' is not supported");
        }
    }

    private static void setBasicAttribute(Path path, String name, Object value,
                                          LinkOption... options) throws IOException {
        boolean lastModified = name.equals("lastModifiedTime");
        boolean lastAccessed = name.equals("lastAccessTime");
        boolean created = name.equals("creationTime");
        if (!lastModified && !lastAccessed && !created) {
            throw new IllegalArgumentException("'basic:" + name + "' is not recognized");
        }
        GocryptFsPath p = resolve(path, options);
        core(p).setTimes(p.toString(),
                lastModified ? (FileTime) value : null,
                lastAccessed ? (FileTime) value : null,
                created ? (FileTime) value : null);
    }

    private static void setPosixAttribute(Path path, String name, Object value,
                                          LinkOption... options) throws IOException {
        GocryptFsPosixFileAttributeView view = newPosixView(path, options);
        switch (name) {
            case "permissions":
                view.setPermissions((Set<PosixFilePermission>) value);
                return;
            case "owner":
                view.setOwner((UserPrincipal) value);
                return;
            case "group":
                view.setGroup((GroupPrincipal) value);
                return;
            case "lastModifiedTime":
                view.setTimes((FileTime) value, null, null);
                return;
            case "lastAccessTime":
                view.setTimes(null, (FileTime) value, null);
                return;
            case "creationTime":
                view.setTimes(null, null, (FileTime) value);
                return;
            default:
                throw new IllegalArgumentException("'posix:" + name + "' is not recognized");
        }
    }

    private static GocryptFsPosixFileAttributeView newPosixView(Path path,
                                                                LinkOption... options) {
        GocryptFsFileSystem fs = (GocryptFsFileSystem) path.getFileSystem();
        return new GocryptFsPosixFileAttributeView(fs, toAbsolute(path), !noFollow(options));
    }

    private static GocryptFsOwnerFileAttributeView newOwnerView(Path path,
                                                                LinkOption... options) {
        GocryptFsFileSystem fs = (GocryptFsFileSystem) path.getFileSystem();
        return new GocryptFsOwnerFileAttributeView(fs, toAbsolute(path), !noFollow(options));
    }
}
