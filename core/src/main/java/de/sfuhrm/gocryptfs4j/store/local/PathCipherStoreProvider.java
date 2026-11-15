package de.sfuhrm.gocryptfs4j.store.local;

import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.CipherStoreProvider;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link CipherStoreProvider} that hands out {@link PathCipherStore} instances
 * for the local filesystem under the {@code file} URI scheme.
 *
 * <p>The URI path is interpreted as the ciphertext root directory, for example
 * {@code file:///data/cipher}. This mirrors the {@code file} scheme used by
 * {@link java.nio.file.Paths#get(URI)}.</p>
 */
public final class PathCipherStoreProvider implements CipherStoreProvider {

    @Override
    public String scheme() {
        return "file";
    }

    @Override
    public CipherStore newStore(URI uri, Map<String, ?> env) throws IOException {
        return new PathCipherStore(Paths.get(Objects.requireNonNull(uri, "uri")));
    }
}
