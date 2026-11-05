package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.URI;
import java.nio.file.ClosedFileSystemException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.WatchService;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link FileSystem} view over a gocryptfs cipher directory.
 *
 * <p>All {@link Path}s obtained from this filesystem are plaintext paths rooted
 * at {@code "/"}. The filesystem is backed by a {@link GocryptFs} instance and
 * is registered with its {@link GocryptFsProvider} under the cipher directory
 * key until it is closed.</p>
 *
 * <p>The backing {@code CipherStore} is always a local
 * {@code de.sfuhrm.gocryptfs4j.store.local.PathCipherStore}: the file store
 * (space, read-only flag, POSIX support) is resolved from the local cipher
 * directory path. Non-local stores such as the {@code memory} store are not
 * supported through the NIO view.</p>
 */
public final class GocryptFsFileSystem extends FileSystem {

    /** The provider that created this filesystem. */
    private final GocryptFsProvider provider;

    /** The core gocryptfs instance. */
    private final GocryptFs core;

    /** The backing cipher store, owned and closed by this filesystem. */
    private final CipherStore store;

    /** The absolute, normalized cipher directory key. */
    private final String key;

    /** The key under which this filesystem is registered with the provider. */
    private final String registrationKey;

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

    /** The watch services created by this filesystem, closed on {@link #close()}. */
    private final Set<GocryptFsWatchService> watchServices = ConcurrentHashMap.newKeySet();

    /** Whether backslashes are treated as path separators. */
    private final boolean windowsSeparators;

    /**
     * Creates a filesystem. Called by the provider when a cipher directory is
     * opened.
     *
     * @param provider          the provider that created this filesystem
     * @param store             the backing cipher store, owned and closed by this filesystem
     * @param core              the core gocryptfs instance
     * @param key               the absolute, normalized cipher directory key
     * @param windowsSeparators whether {@code "\"} is treated as a path separator
     */
    GocryptFsFileSystem(GocryptFsProvider provider, CipherStore store, GocryptFs core,
                        String key, boolean windowsSeparators) {
        this(provider, store, core, key, windowsSeparators, false);
    }

    /**
     * Creates a filesystem. Called by the provider when a cipher directory is
     * opened.
     *
     * @param provider          the provider that created this filesystem
     * @param store             the backing cipher store, owned and closed by this filesystem
     * @param core              the core gocryptfs instance
     * @param key               the absolute, normalized cipher directory key
     * @param windowsSeparators whether {@code "\"} is treated as a path separator
     * @param readOnlyRequested whether the caller explicitly opened it read-only
     */
    GocryptFsFileSystem(GocryptFsProvider provider, CipherStore store, GocryptFs core,
                        String key, boolean windowsSeparators, boolean readOnlyRequested) {
        this.provider = provider;
        this.store = store;
        this.core = core;
        this.key = key;
        this.registrationKey = readOnlyRequested ? readOnlyKey(key) : key;
        this.windowsSeparators = windowsSeparators;
        this.uri = URI.create("gocryptfs://" + urlEncode(key) + "/");
        this.root = GocryptFsPath.absolute(this, "/");
        this.userPrincipalLookupService = new GocryptFsUserPrincipalLookupService();
        FileStore backingStore = fileStore(key);
        this.supportsPosix = backingStore != null && backingStore.supportsFileAttributeView("posix");
        this.readOnly = readOnlyRequested
                || (backingStore != null && backingStore.isReadOnly());
    }

    /**
     * Returns the provider registration key for a read-only filesystem.
     *
     * @param key the absolute, normalized cipher directory key
     * @return the registration key
     */
    static String readOnlyKey(String key) {
        return key + "\u0000read-only";
    }

    /**
     * Returns the backing file store of the cipher directory.
     *
     * @param key the absolute, normalized cipher directory key
     * @return the backing file store, or {@code null} if it cannot be determined
     */
    private static @Nullable FileStore fileStore(String key) {
        try {
            return Files.getFileStore(Paths.get(key));
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
    @SuppressWarnings("JdkObsolete") // Charset overload is unavailable on the Java 8 target
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
     * Returns the key under which this filesystem is registered with the
     * provider. Read-only filesystems use a distinct key so they can coexist
     * with a writable filesystem on the same cipher directory.
     *
     * @return the provider registration key
     */
    String registrationKey() {
        return registrationKey;
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
     * Returns whether backslashes are treated as path separators.
     *
     * @return {@code true} if {@code "\"} is treated as a path separator
     */
    boolean windowsSeparators() {
        return windowsSeparators;
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
     * Registers a watch service so it is closed when the filesystem closes.
     *
     * @param watchService the watch service to track
     */
    void addWatchService(GocryptFsWatchService watchService) {
        watchServices.add(watchService);
    }

    /**
     * Unregisters a watch service after it has been closed.
     *
     * @param watchService the watch service to stop tracking
     */
    void removeWatchService(GocryptFsWatchService watchService) {
        watchServices.remove(watchService);
    }

    /**
     * Closes the filesystem, releasing the core gocryptfs instance and the
     * backing cipher store, and unregistering it from the provider. Closing an
     * already-closed filesystem has no effect.
     *
     * @throws IOException on filesystem errors
     */
    @Override
    public void close() throws IOException {
        if (open) {
            open = false;
            closeWatchServices();
            try {
                core.close();
            } finally {
                store.close();
            }
            provider.remove(this);
        }
    }

    /**
     * Closes and unregisters all outstanding watch services so that threads
     * blocked in {@link java.nio.file.WatchService#take()} wake up.
     */
    private void closeWatchServices() {
        for (GocryptFsWatchService watchService : new ArrayList<>(watchServices)) {
            watchService.close();
        }
        watchServices.clear();
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
