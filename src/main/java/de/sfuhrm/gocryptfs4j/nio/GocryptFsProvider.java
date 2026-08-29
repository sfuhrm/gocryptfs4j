package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.fs.DirEntry;
import de.sfuhrm.gocryptfs4j.fs.GocryptFs;
import de.sfuhrm.gocryptfs4j.fs.CipherFile;

import java.io.IOException;
import java.net.URI;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link FileSystemProvider} for gocryptfs cipher directories.
 *
 * <p>Register via {@code META-INF/services/java.nio.file.spi.FileSystemProvider}
 * to use {@code FileSystems.newFileSystem(URI.create("gocryptfs:///"), env)}, or
 * instantiate directly. The environment must contain {@code cipherDir} (a
 * {@link Path} or {@link String}) and {@code password} (a {@link String} or
 * {@code char[]}).</p>
 */
public final class GocryptFsProvider extends FileSystemProvider {

    public static final String SCHEME = "gocryptfs";

    private final Map<String, GocryptFsFileSystem> filesystems = new ConcurrentHashMap<>();

    /** Opens a filesystem directly, without a URI. */
    public FileSystem newFileSystem(Path cipherDir, char[] password) throws IOException {
        GocryptFs core = GocryptFs.open(cipherDir, password);
        String key = cipherDir.toAbsolutePath().normalize().toString();
        GocryptFsFileSystem fs = new GocryptFsFileSystem(this, core, key);
        filesystems.put(key, fs);
        return fs;
    }

    @Override
    public String getScheme() {
        return SCHEME;
    }

    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        if (!SCHEME.equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("uri scheme is not '" + SCHEME + "': " + uri);
        }
        Object cipherDir = env == null ? null : env.get("cipherDir");
        Object password = env == null ? null : env.get("password");
        if (cipherDir == null || password == null) {
            throw new IllegalArgumentException(
                    "environment must contain 'cipherDir' and 'password'");
        }
        Path dir = cipherDir instanceof Path
                ? (Path) cipherDir : Path.of(cipherDir.toString());
        char[] pw = password instanceof char[]
                ? (char[]) password : password.toString().toCharArray();
        return newFileSystem(dir, pw);
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        String key = GocryptFsFileSystem.urlDecode(uri.getHost());
        GocryptFsFileSystem fs = filesystems.get(key);
        if (fs == null && filesystems.size() == 1) {
            fs = filesystems.values().iterator().next();
        }
        if (fs == null) {
            throw new java.nio.file.FileSystemNotFoundException("no filesystem for " + uri);
        }
        return fs;
    }

    @Override
    public Path getPath(URI uri) {
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

    // ------------------------------------------------------------------
    // Channels, streams
    // ------------------------------------------------------------------

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options,
                                              FileAttribute<?>... attrs) throws IOException {
        GocryptFsPath p = toAbsolute(path);
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
        if (create && !exists) {
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

    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir,
                                                    DirectoryStream.Filter<? super Path> filter)
            throws IOException {
        GocryptFsPath d = toAbsolute(dir);
        GocryptFs fs = core(d);
        List<Path> entries = new ArrayList<>();
        for (DirEntry e : fs.list(d.toString())) {
            Path child = d.resolve(e.plainName());
            if (filter == null || filter.accept(child)) {
                entries.add(child);
            }
        }
        return new GocryptFsDirectoryStream(entries);
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        GocryptFsPath d = toAbsolute(dir);
        core(d).mkdir(d.toString());
    }

    @Override
    public void delete(Path path) throws IOException {
        GocryptFsPath p = toAbsolute(path);
        core(p).delete(p.toString());
    }

    // ------------------------------------------------------------------
    // Copy / move
    // ------------------------------------------------------------------

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        GocryptFsPath s = toAbsolute(source);
        GocryptFsPath t = toAbsolute(target);
        GocryptFs fs = core(s);
        Set<CopyOption> opts = options.length == 0 ? Set.of() : Set.of(options);
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
            byte[] data = fs.readAll(s.toString());
            fs.createFile(t.toString());
            fs.write(t.toString(), 0, data);
        }
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
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

    @Override
    public boolean isSameFile(Path path, Path path2) throws IOException {
        GocryptFsPath a = toAbsolute(path);
        GocryptFsPath b = toAbsolute(path2);
        if (a.getFileSystem() != b.getFileSystem()) {
            return false;
        }
        Object ka = core(a).stat(a.toString()).fileKey();
        Object kb = core(b).stat(b.toString()).fileKey();
        return ka != null && ka.equals(kb);
    }

    @Override
    public boolean isHidden(Path path) {
        Path name = path.getFileName();
        return name != null && name.toString().startsWith(".");
    }

    @Override
    public FileStore getFileStore(Path path) {
        return new GocryptFsFileStore((GocryptFsFileSystem) path.getFileSystem());
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        GocryptFsPath p = toAbsolute(path);
        core(p).stat(p.toString());
    }

    @Override
    @SuppressWarnings("unchecked")
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type,
                                                                LinkOption... options) {
        if (type == BasicFileAttributeView.class) {
            return (V) new GocryptFsBasicFileAttributeView(
                    (GocryptFsFileSystem) path.getFileSystem(), toAbsolute(path));
        }
        return null;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <A extends BasicFileAttributes> A readAttributes(Path path, Class<A> type,
                                                            LinkOption... options)
            throws IOException {
        if (type == BasicFileAttributes.class) {
            GocryptFsPath p = toAbsolute(path);
            return (A) new GocryptFsFileAttributes(core(p).stat(p.toString()));
        }
        throw new UnsupportedOperationException("unsupported attribute type: " + type);
    }

    @Override
    public Map<String, Object> readAttributes(Path path, String attributes, LinkOption... options)
            throws IOException {
        GocryptFsPath p = toAbsolute(path);
        DirEntry e = core(p).stat(p.toString());
        Map<String, Object> result = new HashMap<>();
        for (String token : attributes.split(",")) {
            String attr = token.trim();
            String key = attr;
            String name = attr.contains(":") ? attr.substring(attr.indexOf(':') + 1) : attr;
            Object value = attributeValue(e, name);
            if (value == null) {
                throw new IllegalArgumentException("unsupported attribute: " + attr);
            }
            result.put(key, value);
        }
        return result;
    }

    private static Object attributeValue(DirEntry e, String name) {
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
                return null;
        }
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, LinkOption... options)
            throws IOException {
        GocryptFsPath p = toAbsolute(path);
        String name = attribute.contains(":") ? attribute.substring(attribute.indexOf(':') + 1)
                : attribute;
        switch (name) {
            case "lastModifiedTime":
                core(p).setTimes(p.toString(), (FileTime) value, null, null);
                return;
            case "lastAccessTime":
                core(p).setTimes(p.toString(), null, (FileTime) value, null);
                return;
            case "creationTime":
                core(p).setTimes(p.toString(), null, null, (FileTime) value);
                return;
            default:
                throw new UnsupportedOperationException("unsupported attribute: " + attribute);
        }
    }
}
