package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.WatchService;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * A {@link FileSystem} view over a gocryptfs cipher directory.
 *
 * <p>All {@link Path}s obtained from this filesystem are plaintext paths rooted
 * at {@code "/"}. The filesystem is backed by a {@link GocryptFs} instance and
 * is registered with its {@link GocryptFsProvider} under the cipher directory
 * key until it is closed.</p>
 */
public final class GocryptFsFileSystem extends FileSystem {

    /** The provider that created this filesystem. */
    private final GocryptFsProvider provider;

    /** The core gocryptfs instance. */
    private final GocryptFs core;

    /** The absolute, normalized cipher directory key. */
    private final String key;

    /** The URI identifying this filesystem. */
    private final URI uri;

    /** The root path. */
    private final GocryptFsPath root;

    /** The principal lookup service. */
    private final GocryptFsUserPrincipalLookupService userPrincipalLookupService;

    /** Whether the backing filesystem supports POSIX attributes. */
    private final boolean supportsPosix;

    /** Whether the backing filesystem is read-only. */
    private final boolean readOnly;

    /** Whether the filesystem is still open. */
    private volatile boolean open = true;

    /**
     * Creates a filesystem. Called by the provider when a cipher directory is
     * opened.
     *
     * @param provider the provider that created this filesystem
     * @param core     the core gocryptfs instance
     * @param key      the absolute, normalized cipher directory key
     */
    GocryptFsFileSystem(GocryptFsProvider provider, GocryptFs core, String key) {
        this.provider = provider;
        this.core = core;
        this.key = key;
        this.uri = URI.create("gocryptfs://" + urlEncode(key) + "/");
        this.root = GocryptFsPath.absolute(this, "/");
        this.userPrincipalLookupService = new GocryptFsUserPrincipalLookupService(this);
        FileStore store = fileStore(core);
        this.supportsPosix = store != null && store.supportsFileAttributeView("posix");
        this.readOnly = store != null && store.isReadOnly();
    }

    /**
     * Returns the backing file store.
     *
     * @param core the core gocryptfs instance
     * @return the backing file store, or {@code null} if it cannot be determined
     */
    private static @Nullable FileStore fileStore(GocryptFs core) {
        try {
            return Files.getFileStore(core.cipherRoot());
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Percent-encodes a string for use as a URI authority.
     *
     * @param s the string to encode
     * @return the encoded string
     */
    private static String urlEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
                    || b == '-' || b == '_' || b == '.' || b == '~') {
                sb.append((char) b);
            } else {
                sb.append('%');
                sb.append(String.format("%02X", b));
            }
        }
        return sb.toString();
    }

    /**
     * Decodes a percent-encoded URI authority.
     *
     * @param s the encoded string
     * @return the decoded string, or the input if decoding fails
     */
    static String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    /**
     * Returns the core gocryptfs instance.
     *
     * @return the core gocryptfs instance
     */
    GocryptFs core() {
        return core;
    }

    /**
     * Returns whether the backing filesystem supports POSIX attributes.
     *
     * @return {@code true} if POSIX attributes are supported
     */
    boolean supportsPosix() {
        return supportsPosix;
    }

    /**
     * Returns the cipher directory key.
     *
     * @return the cipher directory key
     */
    String key() {
        return key;
    }

    /**
     * Returns the URI identifying this filesystem.
     *
     * @return the filesystem URI
     */
    URI uri() {
        return uri;
    }

    /**
     * Returns the root path.
     *
     * @return the root path
     */
    GocryptFsPath getRootPath() {
        return root;
    }

    /**
     * Returns the provider that created this filesystem.
     *
     * @return the provider
     */
    @Override
    public GocryptFsProvider provider() {
        return provider;
    }

    /**
     * Returns whether the filesystem is open.
     *
     * @return {@code true} if the filesystem is open
     */
    @Override
    public boolean isOpen() {
        return open;
    }

    /**
     * Returns whether the filesystem is read-only. This reflects the backing
     * file store.
     *
     * @return {@code true} if the backing store is read-only
     */
    @Override
    public boolean isReadOnly() {
        return readOnly;
    }

    /**
     * Returns the name separator.
     *
     * @return the string {@code "/"}
     */
    @Override
    public String getSeparator() {
        return "/";
    }

    /**
     * Returns the root directories of this filesystem.
     *
     * @return a single-element iterable containing the root path
     */
    @Override
    public Iterable<Path> getRootDirectories() {
        return Collections.singletonList(root);
    }

    /**
     * Returns the file stores of this filesystem.
     *
     * @return a single-element iterable containing the file store
     */
    @Override
    public Iterable<FileStore> getFileStores() {
        return Collections.singletonList(new GocryptFsFileStore(this));
    }

    /**
     * Returns the names of the supported file attribute views: always
     * {@code basic} and, when the backing filesystem supports POSIX,
     * {@code posix} and {@code owner}.
     *
     * @return the supported view names
     */
    @Override
    public Set<String> supportedFileAttributeViews() {
        Set<String> views = new LinkedHashSet<>();
        views.add("basic");
        if (supportsPosix) {
            views.add("posix");
            views.add("owner");
        }
        return Collections.unmodifiableSet(views);
    }

    /**
     * Converts a path string, or a sequence of strings, to a {@link Path}.
     *
     * @param first the first path string
     * @param more  additional path strings to join
     * @return the path
     * @throws NullPointerException if {@code first} or {@code more} is {@code null}
     */
    @Override
    public Path getPath(String first, String... more) {
        Objects.requireNonNull(first, "first");
        Objects.requireNonNull(more, "more");
        String joined = first;
        for (String m : more) {
            joined = joined.endsWith("/") ? joined + m : joined + "/" + m;
        }
        boolean abs = joined.startsWith("/");
        return new GocryptFsPath(this, joined, abs);
    }

    /**
     * Creates a path matcher for the given {@code glob} or {@code regex} pattern.
     *
     * @param syntaxAndPattern the syntax and pattern, for example {@code "glob:*.txt"}
     * @return the path matcher
     * @throws NullPointerException if {@code syntaxAndPattern} is {@code null}
     * @throws IllegalArgumentException if the syntax is unknown or the pattern is invalid
     */
    @Override
    public PathMatcher getPathMatcher(String syntaxAndPattern) {
        Objects.requireNonNull(syntaxAndPattern, "syntaxAndPattern");
        return GocryptFsPathMatcher.create(syntaxAndPattern);
    }

    /**
     * Returns the user principal lookup service.
     *
     * @return the user principal lookup service
     */
    @Override
    public UserPrincipalLookupService getUserPrincipalLookupService() {
        return userPrincipalLookupService;
    }

    /**
     * Creates a new watch service.
     *
     * @return the watch service
     * @throws ClosedFileSystemException if the filesystem is closed
     */
    @Override
    public WatchService newWatchService() {
        if (!open) {
            throw new ClosedFileSystemException();
        }
        return new GocryptFsWatchService(this);
    }

    /**
     * Closes the filesystem, releasing the core gocryptfs instance and
     * unregistering it from the provider. Closing an already-closed filesystem
     * has no effect.
     *
     * @throws IOException on filesystem errors
     */
    @Override
    public void close() throws IOException {
        if (open) {
            open = false;
            core.close();
            provider.remove(this);
        }
    }

    /**
     * Returns the string form of this filesystem, which is its URI.
     *
     * @return the filesystem URI
     */
    @Override
    public String toString() {
        return uri.toString();
    }
}
