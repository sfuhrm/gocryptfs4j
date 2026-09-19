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
import java.nio.file.AccessDeniedException;
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
import java.nio.file.attribute.FileTime;
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
        boolean write = options.contains(StandardOpenOption.WRITE)
                || options.contains(StandardOpenOption.APPEND);
        boolean truncate = options.contains(StandardOpenOption.TRUNCATE_EXISTING);
        boolean append = options.contains(StandardOpenOption.APPEND);

        boolean exists = java.nio.file.Files.exists(r.cipherPath, LinkOption.NOFOLLOW_LINKS);
        if (createNew && exists) {
            throw new FileAlreadyExistsException(p.toString());
        }
        if ((create || createNew) && !exists) {
            fs.createFile(p.toString());
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
        return new GocryptFsFileChannel(cf, write, position);
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
     * Copies a file or directory tree.
     *
     * @throws NullPointerException if {@code source} or {@code target} is {@code null}
     */
    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(target, "target");
        GocryptFsPath s = toAbsolute(source);
        GocryptFsPath t = toAbsolute(target);
        GocryptFs fs = core(s);
        Set<CopyOption> opts = options.length == 0
                ? Collections.<CopyOption>emptySet()
                : new HashSet<>(Arrays.asList(options));
        boolean replace = opts.contains(StandardCopyOption.REPLACE_EXISTING);

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
        } else if (se.isSymbolicLink()) {
            fs.createSymlink(t.toString(), fs.readSymlinkTarget(s.toString()));
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
        }
    }

    /**
     * Moves a file or directory tree.
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
        copy(source, target, options);
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
     * Checks the existence of a path.
     *
     * @throws NullPointerException if {@code path} is {@code null}
     */
    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        Objects.requireNonNull(path, "path");
        GocryptFsPath p = resolve(path);
        DirEntry e = core(p).stat(p.toString());
        for (AccessMode mode : modes) {
            if (mode == AccessMode.EXECUTE && !e.isDirectory()) {
                throw new AccessDeniedException(p.toString());
            }
        }
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
        if (type == BasicFileAttributeView.class) {
            return (V) new GocryptFsBasicFileAttributeView(
                    (GocryptFsFileSystem) path.getFileSystem(), toAbsolute(path),
                    !noFollow(options));
        }
        return null;
    }

    /**
     * Reads a file's attributes.
     *
     * @throws NullPointerException if {@code path} or {@code type} is {@code null}
     */
    @Override
    @SuppressWarnings("unchecked")
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type,
                                                            LinkOption... options)
            throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(type, "type");
        if (type == BasicFileAttributes.class) {
            GocryptFsPath p = resolve(path, options);
            return (A) new GocryptFsFileAttributes(core(p).stat(p.toString()));
        }
        throw new UnsupportedOperationException("unsupported attribute type: " + type);
    }

    /**
     * Reads a set of attributes by name.
     *
     * <p>The {@code attributes} string has the form {@code [view:]attribute-list}
     * where {@code view} defaults to {@code basic} and {@code attribute-list} is a
     * comma separated list of attribute names. The special name {@code *} selects
     * all basic attributes.</p>
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
        GocryptFsPath p = resolve(path, options);
        return basicAttributes(core(p).stat(p.toString()), attributes);
    }

    /** The names of all attributes of the basic view, in a stable order. */
    private static final List<String> BASIC_ATTRIBUTES = Arrays.asList(
            "size", "creationTime", "lastModifiedTime", "lastAccessTime",
            "isRegularFile", "isDirectory", "isSymbolicLink", "isOther", "fileKey");

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
        String names = stripBasicView(attributes);
        Map<String, Object> result = new HashMap<>();
        for (String token : names.split(",")) {
            if (token.equals("*")) {
                for (String attribute : BASIC_ATTRIBUTES) {
                    result.put(attribute, basicAttribute(entry, attribute));
                }
            } else {
                result.put(token, basicAttribute(entry, token));
            }
        }
        return result;
    }

    /**
     * Strips the optional {@code view:} prefix from an attribute specification
     * and validates that the named view is the basic view.
     *
     * @param specification the {@code [view:]name} or {@code [view:]name-list} string
     * @return the part after the optional {@code view:} prefix
     * @throws UnsupportedOperationException if a view other than {@code basic} is named
     */
    private static String stripBasicView(String specification) {
        int colon = specification.indexOf(':');
        if (colon < 0) {
            return specification;
        }
        String view = specification.substring(0, colon);
        if (!"basic".equals(view)) {
            throw new UnsupportedOperationException("view '" + view + "' is not supported");
        }
        return specification.substring(colon + 1);
    }

    private static Object basicAttribute(DirEntry e, String name) {
        switch (name) {
            case "size":
                return e.size();
            case "creationTime":
                return e.creationTime();
            case "lastModifiedTime":
                return e.lastModifiedTime();
            case "lastAccessTime":
                return e.lastAccessTime();
            case "isDirectory":
                return e.isDirectory();
            case "isRegularFile":
                return e.isRegularFile();
            case "isSymbolicLink":
                return e.isSymbolicLink();
            case "isOther":
                return e.kind() == DirEntry.Kind.OTHER;
            case "fileKey":
                return e.fileKey();
            default:
                throw new IllegalArgumentException("'" + name + "' is not recognized");
        }
    }

    /**
     * Sets a file attribute by name.
     *
     * <p>The {@code attribute} string has the form {@code [view:]attribute-name}
     * where {@code view} defaults to {@code basic}. Only the settable basic
     * attributes {@code lastModifiedTime}, {@code lastAccessTime} and
     * {@code creationTime} are supported.</p>
     *
     * @throws NullPointerException if {@code path} or {@code attribute} is {@code null}
     * @throws UnsupportedOperationException if the requested attribute view is not available
     * @throws IllegalArgumentException if the attribute is not recognized or is not settable
     */
    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options)
            throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(attribute, "attribute");
        String name = stripBasicView(attribute);
        boolean lastModified = "lastModifiedTime".equals(name);
        boolean lastAccessed = "lastAccessTime".equals(name);
        boolean created = "creationTime".equals(name);
        if (!lastModified && !lastAccessed && !created) {
            throw new IllegalArgumentException("'basic:" + name + "' is not recognized");
        }
        GocryptFsPath p = resolve(path, options);
        core(p).setTimes(p.toString(),
                lastModified ? (FileTime) value : null,
                lastAccessed ? (FileTime) value : null,
                created ? (FileTime) value : null);
    }
}
