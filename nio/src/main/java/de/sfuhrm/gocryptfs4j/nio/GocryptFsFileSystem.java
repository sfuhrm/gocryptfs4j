package de.sfuhrm.gocryptfs4j.nio;

import de.sfuhrm.gocryptfs4j.fs.GocryptFs;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.WatchService;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.List;
import java.util.Set;

/**
 * A {@link FileSystem} view over a gocryptfs cipher directory.
 *
 * <p>All {@link Path}s obtained from this filesystem are plaintext paths rooted
 * at {@code "/"}.</p>
 */
public final class GocryptFsFileSystem extends FileSystem {

    private final GocryptFsProvider provider;
    private final GocryptFs core;
    private final String key;
    private final URI uri;
    private final GocryptFsPath root;
    private volatile boolean open = true;

    GocryptFsFileSystem(GocryptFsProvider provider, GocryptFs core, String key) {
        this.provider = provider;
        this.core = core;
        this.key = key;
        this.uri = URI.create("gocryptfs://" + urlEncode(key) + "/");
        this.root = GocryptFsPath.absolute(this, "/");
    }

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

    static String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return s;
        }
    }

    GocryptFs core() {
        return core;
    }

    String key() {
        return key;
    }

    URI uri() {
        return uri;
    }

    GocryptFsPath getRootPath() {
        return root;
    }

    @Override
    public GocryptFsProvider provider() {
        return provider;
    }

    @Override
    public boolean isOpen() {
        return open;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public String getSeparator() {
        return "/";
    }

    @Override
    public Iterable<Path> getRootDirectories() {
        return List.of(root);
    }

    @Override
    public Iterable<FileStore> getFileStores() {
        return List.of(new GocryptFsFileStore(this));
    }

    @Override
    public Set<String> supportedFileAttributeViews() {
        return Set.of("basic");
    }

    @Override
    public Path getPath(String first, String... more) {
        String joined = first;
        for (String m : more) {
            joined = joined.endsWith("/") ? joined + m : joined + "/" + m;
        }
        boolean abs = joined.startsWith("/");
        return new GocryptFsPath(this, joined, abs);
    }

    @Override
    public PathMatcher getPathMatcher(String syntaxAndPattern) {
        throw new UnsupportedOperationException("PathMatcher is not supported");
    }

    @Override
    public UserPrincipalLookupService getUserPrincipalLookupService() {
        throw new UnsupportedOperationException("UserPrincipalLookupService is not supported");
    }

    @Override
    public WatchService newWatchService() {
        throw new UnsupportedOperationException("WatchService is not supported");
    }

    @Override
    public void close() throws IOException {
        if (open) {
            open = false;
            core.close();
            provider.remove(this);
        }
    }

    @Override
    public String toString() {
        return uri.toString();
    }
}
