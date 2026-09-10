package de.sfuhrm.gocryptfs4j.nio;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
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
 */
final class GocryptFsPath implements Path {

    private final GocryptFsFileSystem fs;
    private final String path;
    private final boolean absolute;

    GocryptFsPath(GocryptFsFileSystem fs, String path, boolean absolute) {
        this.fs = fs;
        this.path = normalize(path);
        this.absolute = absolute;
    }

    static GocryptFsPath absolute(GocryptFsFileSystem fs, String path) {
        return new GocryptFsPath(fs, path, true);
    }

    /** Splits a normalized path into its name elements (no empty or "." or ".."). */
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

    @Override
    public FileSystem getFileSystem() {
        return fs;
    }

    @Override
    public boolean isAbsolute() {
        return absolute;
    }

    @Override
    public Path getRoot() {
        return absolute ? fs.getRootPath() : null;
    }

    @Override
    public Path getFileName() {
        String[] n = names();
        if (n.length == 0) {
            return null;
        }
        return new GocryptFsPath(fs, n[n.length - 1], false);
    }

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

    @Override
    public int getNameCount() {
        return names().length;
    }

    @Override
    public Path getName(int index) {
        String[] n = names();
        if (index < 0 || index >= n.length) {
            throw new IllegalArgumentException("index out of range: " + index);
        }
        return new GocryptFsPath(fs, n[index], false);
    }

    @Override
    public Path subpath(int beginIndex, int endIndex) {
        String[] n = names();
        if (beginIndex < 0 || endIndex > n.length || beginIndex >= endIndex) {
            throw new IllegalArgumentException("invalid subpath range");
        }
        String sub = String.join("/", Arrays.copyOfRange(n, beginIndex, endIndex));
        return new GocryptFsPath(fs, sub, false);
    }

    @Override
    public boolean startsWith(Path other) {
        if (!(other instanceof GocryptFsPath)) {
            return false;
        }
        return startsWith(other.toString());
    }

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

    @Override
    public boolean endsWith(Path other) {
        if (!(other instanceof GocryptFsPath)) {
            return false;
        }
        return endsWith(other.toString());
    }

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

    @Override
    public Path normalize() {
        return new GocryptFsPath(fs, path, absolute);
    }

    @Override
    public Path resolve(Path other) {
        if (other.isAbsolute()) {
            return other;
        }
        return resolve(other.toString());
    }

    @Override
    public Path resolve(String other) {
        if (other == null) {
            return this;
        }
        String o = other.replace('\\', '/');
        if (o.startsWith("/")) {
            return new GocryptFsPath(fs, o, true);
        }
        String base = absolute ? path : path;
        String joined = base.equals("/") || base.isEmpty() ? o : base + "/" + o;
        return new GocryptFsPath(fs, joined, absolute);
    }

    @Override
    public Path resolveSibling(Path other) {
        Path parent = getParent();
        if (parent == null) {
            return other;
        }
        return parent.resolve(other);
    }

    @Override
    public Path resolveSibling(String other) {
        Path parent = getParent();
        if (parent == null) {
            return fs.getPath(other);
        }
        return parent.resolve(other);
    }

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

    @Override
    public Path toAbsolutePath() {
        if (absolute) {
            return this;
        }
        return new GocryptFsPath(fs, "/" + path, true);
    }

    @Override
    public Path toRealPath(LinkOption... options) {
        return toAbsolutePath().normalize();
    }

    @Override
    public File toFile() {
        throw new UnsupportedOperationException("gocryptfs paths are not backed by java.io.File");
    }

    @Override
    public URI toUri() {
        return URI.create(fs.uri().toString().replaceAll("/$", "") + (absolute ? path : "/" + path));
    }

    @Override
    public Iterator<Path> iterator() {
        String[] n = names();
        List<Path> list = new ArrayList<>(n.length);
        for (String s : n) {
            list.add(new GocryptFsPath(fs, s, false));
        }
        return list.iterator();
    }

    @Override
    public int compareTo(Path other) {
        return path.compareTo(other.toString());
    }

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

    @Override
    public int hashCode() {
        return Objects.hash(fs, path, absolute);
    }

    @Override
    public String toString() {
        if (absolute) {
            return path;
        }
        return path.isEmpty() ? "" : path;
    }

    @Override
    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>[] events, WatchEvent.Modifier... modifiers) {
        throw new UnsupportedOperationException("watch service not supported");
    }

    @Override
    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>... events) {
        throw new UnsupportedOperationException("watch service not supported");
    }
}
