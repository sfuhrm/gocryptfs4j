package de.sfuhrm.gocryptfs4j.store.memory;

import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.CipherStoreProvider;

import java.net.URI;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link CipherStoreProvider} that hands out {@link MapCipherStore} instances
 * under the {@code memory} URI scheme.
 *
 * <p>The store is ephemeral: every {@link #newStore(URI, Map)} returns a fresh,
 * empty in-memory store, so the {@code memory} scheme is best suited to tests
 * and examples rather than persistence.</p>
 */
public final class MapCipherStoreProvider implements CipherStoreProvider {

    @Override
    public String scheme() {
        return "memory";
    }

    @Override
    public CipherStore newStore(URI uri, Map<String, ?> env) {
        Objects.requireNonNull(uri, "uri");
        return new MapCipherStore();
    }
}
