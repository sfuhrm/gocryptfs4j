package de.sfuhrm.gocryptfs4j.store;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Resolves a {@link URI} to a {@link CipherStore} by dispatching on its scheme
 * to a registered {@link CipherStoreProvider}.
 *
 * <p>Providers are discovered through {@link ServiceLoader}; see
 * {@link CipherStoreProvider} for how to register one.</p>
 */
public final class CipherStores {

    /** All registered providers, discovered once and reused for every lookup. */
    private static final List<CipherStoreProvider> PROVIDERS = loadProviders();

    /** Prevents instantiation. */
    private CipherStores() {
    }

    /**
     * Discovers all {@link CipherStoreProvider} implementations registered via
     * {@link ServiceLoader}. Providers are discovered once and cached, since
     * they are stateless factories and re-discovering them on every call would
     * re-read the service configuration files for no benefit.
     *
     * @return the discovered providers
     */
    private static List<CipherStoreProvider> loadProviders() {
        List<CipherStoreProvider> providers = new ArrayList<>();
        for (CipherStoreProvider provider : ServiceLoader.load(CipherStoreProvider.class)) {
            providers.add(provider);
        }
        return providers;
    }

    /**
     * Opens the {@link CipherStore} identified by {@code uri} using the
     * {@link CipherStoreProvider} registered for its scheme.
     *
     * @param uri the URI identifying the store, for example {@code memory:///}
     *            or {@code s3://bucket/prefix}
     * @param env backend-specific options, or {@code null} for defaults
     * @return the store
     * @throws IOException if no provider handles the scheme, or the store cannot
     *                     be created
     * @throws NullPointerException if {@code uri} is {@code null}
     */
    public static CipherStore newStore(URI uri, Map<String, ?> env) throws IOException {
        Objects.requireNonNull(uri, "uri");
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("URI has no scheme: " + uri);
        }
        for (CipherStoreProvider provider : PROVIDERS) {
            if (provider.scheme().equalsIgnoreCase(scheme)) {
                return provider.newStore(uri, env);
            }
        }
        throw new IOException("no CipherStoreProvider for scheme '" + scheme + "'");
    }
}
