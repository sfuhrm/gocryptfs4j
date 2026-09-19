package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.DirEntry;
import de.sfuhrm.gocryptfs4j.core.GocryptFs;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.WatchEvent;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/**
 * A {@link Path} in the decrypted (plaintext) view of a gocryptfs filesystem.
 *
 * <p>Paths are normalized on creation, use {@code "/"} as separator and are
 * either absolute (rooted at {@code "/"}) or relative. A path is not backed by
 * an {@link java.io.File}.</p>
 */
final class GocryptFsPath implements Path {

    /** The filesystem this path belongs to. */
    private final GocryptFsFileSystem fs;

    /** The normalized string form of the path. */
    private final String path;

    /** Whether the path is absolute. */
    private final boolean absolute;

    /**
     * Creates a path.
     *
     * @param fs       the filesystem this path belongs to
     * @param path     the string form of the path
     * @param absolute whether the path is absolute
     */
    GocryptFsPath(GocryptFsFileSystem fs, String path, boolean absolute) {
        this.fs = fs;
        this.path = normalize(path);
        this.absolute = absolute;
    }

    /**
     * Creates an absolute path.
     *
     * @param fs   the filesystem this path belongs to
     * @param path the absolute string form of the path
     * @return the absolute path
     */
    static GocryptFsPath absolute(GocryptFsFileSystem fs, String path) {
        return new GocryptFsPath(fs, path, true);
    }

    /**
     * Splits the normalized path into its name elements.
     *
     * @return the name elements, never containing empty, {@code "."} or {@code ".."} parts
     */
    private String[] names() {
        if (path.equals("/") || path.isEmpty()) {
            return new String[0];
        }
        String stripped = absolute && path.startsWith("/") ? path.substring(1) : path;
        if (stripped.isEmpty()) {
            return new String[0];
        }
        return stripped.split("/");
    }

    /**
     * Normalizes a path string by replacing backslashes, removing redundant
     * separators and {@code "."} segments and collapsing {@code ".."} segments.
     *
     * @param path the path string
     * @return the normalized path string
     * @throws IllegalArgumentException if {@code path} is {@code null}
     */
    private static String normalize(String path) {
        if (path == null) {
            throw new IllegalArgumentException("null path");
        }
        String cleaned = path.replace('\\', '/');
        boolean isAbs = cleaned.startsWith("/");
        Deque<String> stack = new ArrayDeque<>();
        for (String seg : cleaned.split("/")) {
            if (seg.isEmpty() || seg.equals(".")) {
                continue;
            }
            if (seg.equals("..")) {
                if (!stack.isEmpty()) {
                    stack.removeLast();
                } else if (!isAbs) {
                    stack.addLast("..");
                }
                continue;
            }
            stack.addLast(seg);
        }
        String joined = String.join("/", stack);
        if (isAbs) {
            return "/" + joined;
        }
        return joined.isEmpty() ? "" : joined;
    }

    /**
     * Returns the filesystem this path belongs to.
     *
     * @return the filesystem
     */
    @Override
    public FileSystem getFileSystem() {
        return fs;
    }

    /**
     * Returns whether this path is absolute.
     *
     * @return {@code true} if the path is absolute
     */
    @Override
    public boolean isAbsolute() {
        return absolute;
    }

    /**
     * Returns the root component of this path.
     *
     * @return the root path, or {@code null} for a relative path
     */
    @Override
    public Path getRoot() {
        return absolute ? fs.getRootPath() : null;
    }

    /**
     * Returns the last name element of this path.
     *
     * @return the file name, or {@code null} if the path has no elements
     */
    @Override
    public Path getFileName() {
        String[] n = names();
        if (n.length == 0) {
            return null;
        }
        return new GocryptFsPath(fs, n[n.length - 1], false);
    }

    /**
     * Returns the parent path, or {@code null} if there is none.
     *
     * @return the parent path, or {@code null}
     */
    @Override
    public Path getParent() {
        String[] n = names();
        if (n.length == 0) {
            return null;
        }
        if (n.length == 1) {
            return absolute ? fs.getRootPath() : null;
        }
        String parent = String.join("/", Arrays.copyOf(n, n.length - 1));
        return new GocryptFsPath(fs, (absolute ? "/" : "") + parent, absolute);
    }

    /**
     * Returns the number of name elements.
     *
     * @return the number of name elements
     */
    @Override
    public int getNameCount() {
        return names().length;
    }

    /**
     * Returns the name element at the given index.
     *
     * @param index the index of the element
     * @return the name element
     * @throws IllegalArgumentException if the index is out of range
     */
    @Override
    public Path getName(int index) {
        String[] n = names();
        if (index < 0 || index >= n.length) {
            throw new IllegalArgumentException("index out of range: " + index);
        }
        return new GocryptFsPath(fs, n[index], false);
    }

    /**
     * Returns a subsequence of the name elements as a relative path.
     *
     * @param beginIndex the index of the first element, inclusive
     * @param endIndex   the index after the last element, exclusive
     * @return the relative subpath
     * @throws IllegalArgumentException if the range is invalid
     */
    @Override
    public Path subpath(int beginIndex, int endIndex) {
        String[] n = names();
        if (beginIndex < 0 || endIndex > n.length || beginIndex >= endIndex) {
            throw new IllegalArgumentException("invalid subpath range");
        }
        String sub = String.join("/", Arrays.copyOfRange(n, beginIndex, endIndex));
        return new GocryptFsPath(fs, sub, false);
    }

    /**
     * Tests whether this path starts with the given path.
     *
     * @param other the other path
     * @return {@code true} if this path starts with {@code other}
     */
    @Override
    public boolean startsWith(Path other) {
        if (!(other instanceof GocryptFsPath)) {
            return false;
        }
        return startsWith(other.toString());
    }

    /**
     * Tests whether this path starts with the given path string.
     *
     * @param other the other path string
     * @return {@code true} if this path starts with {@code other}
     */
    @Override
    public boolean startsWith(String other) {
        String otherNorm = normalize(other);
        if (absolute != otherNorm.startsWith("/")) {
            return false;
        }
        if (otherNorm.equals("/") || otherNorm.isEmpty()) {
            return true;
        }
        String thisPath = absolute ? path.substring(1) : path;
        String otherPath = otherNorm.startsWith("/") ? otherNorm.substring(1) : otherNorm;
        return thisPath.equals(otherPath) || thisPath.startsWith(otherPath + "/");
    }

    /**
     * Tests whether this path ends with the given path.
     *
     * @param other the other path
     * @return {@code true} if this path ends with {@code other}
     */
    @Override
    public boolean endsWith(Path other) {
        if (!(other instanceof GocryptFsPath)) {
            return false;
        }
        return endsWith(other.toString());
    }

    /**
     * Tests whether this path ends with the given path string.
     *
     * @param other the other path string
     * @return {@code true} if this path ends with {@code other}
     */
    @Override
    public boolean endsWith(String other) {
        String otherNorm = normalize(other);
        String thisPath = absolute ? path.substring(1) : path;
        String otherPath = otherNorm.startsWith("/") ? otherNorm.substring(1) : otherNorm;
        if (otherPath.isEmpty()) {
            return false;
        }
        return thisPath.equals(otherPath) || thisPath.endsWith("/" + otherPath);
    }

    /**
     * Returns a normalized copy of this path. This implementation stores paths
     * already normalized, so it returns an equal path.
     *
     * @return a normalized path
     */
    @Override
    public Path normalize() {
        return new GocryptFsPath(fs, path, absolute);
    }

    /**
     * Resolves the given path against this path.
     *
     * @param other the path to resolve
     * @return the resolved path
     */
    @Override
    public Path resolve(Path other) {
        if (other.isAbsolute()) {
            return other;
        }
        return resolve(other.toString());
    }

    /**
     * Resolves the given path string against this path.
     *
     * @param other the path string to resolve, or {@code null} for this path
     * @return the resolved path
     */
    @Override
    public Path resolve(String other) {
        if (other == null) {
            return this;
        }
        String o = other.replace('\\', '/');
        if (o.startsWith("/")) {
            return new GocryptFsPath(fs, o, true);
        }
        String base = path;
        String joined = base.equals("/") || base.isEmpty() ? o : base + "/" + o;
        if (absolute && !joined.startsWith("/")) {
            joined = "/" + joined;
        }
        return new GocryptFsPath(fs, joined, absolute);
    }

    /**
     * Resolves the given path against this path's parent.
     *
     * @param other the path to resolve
     * @return the resolved path
     */
    @Override
    public Path resolveSibling(Path other) {
        Path parent = getParent();
        if (parent == null) {
            return other;
        }
        return parent.resolve(other);
    }

    /**
     * Resolves the given path string against this path's parent.
     *
     * @param other the path string to resolve
     * @return the resolved path
     */
    @Override
    public Path resolveSibling(String other) {
        Path parent = getParent();
        if (parent == null) {
            return fs.getPath(other);
        }
        return parent.resolve(other);
    }

    /**
     * Constructs a relative path between this path and the given path.
     *
     * @param other the other path
     * @return the relative path
     * @throws IllegalArgumentException if the other path is of a different
     *                                  kind or has different absoluteness
     */
    @Override
    public Path relativize(Path other) {
        if (!(other instanceof GocryptFsPath) || other.isAbsolute() != absolute) {
            throw new IllegalArgumentException("different types of path");
        }
        String[] thisNames = names();
        String[] otherNames = ((GocryptFsPath) other).names();
        int common = 0;
        while (common < thisNames.length && common < otherNames.length
                && thisNames[common].equals(otherNames[common])) {
            common++;
        }
        List<String> result = new ArrayList<>();
        for (int i = common; i < thisNames.length; i++) {
            result.add("..");
        }
        for (int i = common; i < otherNames.length; i++) {
            result.add(otherNames[i]);
        }
        return new GocryptFsPath(fs, String.join("/", result), false);
    }

    /**
     * Returns the absolute form of this path.
     *
     * @return the absolute path
     */
    @Override
    public Path toAbsolutePath() {
        if (absolute) {
            return this;
        }
        return new GocryptFsPath(fs, "/" + path, true);
    }

    /**
     * Returns the real path, resolving symbolic links unless
     * {@link LinkOption#NOFOLLOW_LINKS} is given.
     *
     * @param options the link options
     * @return the real path
     * @throws IOException on filesystem errors while resolving links
     */
    @Override
    public Path toRealPath(LinkOption... options) throws IOException {
        Path abs = toAbsolutePath().normalize();
        if (Arrays.asList(options).contains(LinkOption.NOFOLLOW_LINKS)) {
            return abs;
        }
        return resolveLinks(abs, 0);
    }

    /**
     * Resolves symbolic links in {@code abs}, returning the fully-resolved path.
     *
     * @param abs   the absolute path to resolve
     * @param depth the current recursion depth
     * @return the resolved path
     * @throws IOException if the link chain is too deep or a lookup fails
     */
    private Path resolveLinks(Path abs, int depth) throws IOException {
        if (depth > 40) {
            throw new IOException("too many levels of symbolic links: " + path);
        }
        GocryptFs core = fs.core();
        Path result = fs.getRootPath();
        int count = abs.getNameCount();
        for (int i = 0; i < count; i++) {
            String elem = abs.getName(i).toString();
            if (elem.equals(".")) {
                continue;
            }
            if (elem.equals("..")) {
                Path parent = result.getParent();
                result = parent == null ? result : parent;
                continue;
            }
            Path candidate = result.resolve(elem);
            try {
                DirEntry e = core.stat(candidate.toString());
                if (e.isSymbolicLink()) {
                    String target = core.readSymlinkTarget(candidate.toString());
                    Path t = target.startsWith("/")
                            ? fs.getPath(target) : result.resolve(target);
                    result = resolveLinks(t.normalize(), depth + 1);
                } else {
                    result = candidate;
                }
            } catch (NoSuchFileException ex) {
                result = candidate;
            }
        }
        return result.normalize();
    }

    /**
     * Always throws, because gocryptfs paths are not backed by a
     * {@link java.io.File}.
     *
     * @return never returns
     * @throws UnsupportedOperationException always
     */
    @Override
    public File toFile() {
        throw new UnsupportedOperationException("gocryptfs paths are not backed by java.io.File");
    }

    /**
     * Returns a URI for this path.
     *
     * @return the URI
     */
    @Override
    public URI toUri() {
        return URI.create(fs.uri().toString().replaceAll("/$", "") + (absolute ? path : "/" + path));
    }

    /**
     * Returns an iterator over the name elements of this path.
     *
     * @return an iterator over the name elements
     */
    @Override
    public Iterator<Path> iterator() {
        String[] n = names();
        List<Path> list = new ArrayList<>(n.length);
        for (String s : n) {
            list.add(new GocryptFsPath(fs, s, false));
        }
        return list.iterator();
    }

    /**
     * Compares this path to another path lexicographically by string form.
     *
     * @param other the other path
     * @return a negative integer, zero or a positive integer as this path is
     *         less than, equal to or greater than {@code other}
     */
    @Override
    public int compareTo(Path other) {
        return path.compareTo(other.toString());
    }

    /**
     * Compares this path to another object. Two paths are equal if they belong
     * to the same filesystem, have the same normalized string form and the same
     * absoluteness.
     *
     * @param o the object to compare to
     * @return {@code true} if the objects are equal
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof GocryptFsPath)) {
            return false;
        }
        GocryptFsPath that = (GocryptFsPath) o;
        return absolute == that.absolute && path.equals(that.path) && fs.equals(that.fs);
    }

    /**
     * Returns a hash code consistent with {@link #equals(Object)}.
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        return Objects.hash(fs, path, absolute);
    }

    /**
     * Returns the string form of this path.
     *
     * @return the path string
     */
    @Override
    public String toString() {
        if (absolute) {
            return path;
        }
        return path.isEmpty() ? "" : path;
    }

    /**
     * Registers this path with a watch service.
     *
     * @param watcher   the watch service
     * @param events    the event kinds to watch for
     * @param modifiers the watch event modifiers; ignored
     * @return the watch key
     * @throws NullPointerException      if {@code watcher} or {@code events} is {@code null}
     * @throws ProviderMismatchException if the watcher belongs to another provider or filesystem
     * @throws IllegalArgumentException  if this path is not absolute
     * @throws IOException on filesystem errors
     */
    @Override
    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>[] events, WatchEvent.Modifier... modifiers) throws IOException {
        if (watcher == null) {
            throw new NullPointerException("watcher");
        }
        if (events == null) {
            throw new NullPointerException("events");
        }
        if (!(watcher instanceof GocryptFsWatchService)) {
            throw new ProviderMismatchException();
        }
        GocryptFsWatchService ws = (GocryptFsWatchService) watcher;
        if (ws.fileSystem() != fs) {
            throw new ProviderMismatchException();
        }
        if (!isAbsolute()) {
            throw new IllegalArgumentException("path must be absolute");
        }
        return ws.register(this, events, modifiers);
    }

    /**
     * Registers this path with a watch service for the given event kinds.
     *
     * @param watcher the watch service
     * @param events  the event kinds to watch for
     * @return the watch key
     * @throws IOException on filesystem errors
     */
    @Override
    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>... events) throws IOException {
        return register(watcher, events, new WatchEvent.Modifier[0]);
    }
}
